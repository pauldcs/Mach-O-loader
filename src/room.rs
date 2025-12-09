use std::{
    ffi::{CStr, CString},
    ptr::NonNull,
};

use goblin::mach::{
    MachO,
    load_command::{CommandVariant, DylibCommand, LcStr, LoadCommand},
    segment::Segment,
};
use libc::_NSGetEnviron;
use mach_sys::{
    mach_types::task_t,
    vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ},
};

use crate::{
    ErrCode,
    utilities::{segment_name_eq, vm_prot_into_string},
    vm,
};

#[derive(Debug, Clone)]
pub struct Room<'a> {
    pub macho: &'a MachO<'a>,
    pub image: &'a [u8],
    pub task: task_t,
    pub vm: NonNull<u8>,
    pub vm_size: usize,
    pub dylibs: Vec<(String, NonNull<libc::c_void>)>,
}

impl<'a> Drop for Room<'a> {
    fn drop(&mut self) {
        let _ = unsafe { vm::memory_dealloc(self.vm, self.vm_size, self.task) };
    }
}

impl<'a> Room<'a> {
    fn new(image: &'a [u8], macho: &'a MachO) -> Self {
        let task = unsafe { vm::self_task_get().unwrap_or_else(|err| panic!("{err}")) };

        let vm_size = {
            let min_addr = macho
                .segments
                .iter()
                .map(|seg| seg.vmaddr)
                .min()
                .unwrap_or(0) as usize;

            let max_addr = macho
                .segments
                .iter()
                .map(|seg| (seg.vmaddr + seg.vmsize) as usize)
                .max()
                .unwrap_or(0);

            max_addr.saturating_sub(min_addr)
        };

        let vm = unsafe { vm::memory_alloc(vm_size, task).unwrap_or_else(|err| panic!("{err}")) };
        eprintln!(
            "{:>15}: allocated {}MB @ [vm 0x{:x}]",
            "room-startup",
            vm_size / 1024 / 1024,
            vm.as_ptr().addr()
        );

        Self {
            vm,
            task,
            macho,
            image,
            dylibs: Vec::new(),
            vm_size,
        }
    }

    pub fn dylibs_load_in(&mut self) {
        for LoadCommand {
            offset: load_command_offset,
            command,
            ..
        } in &self.macho.load_commands
        {
            let (handle, name) = match command {
                CommandVariant::LoadDylib(DylibCommand { dylib, .. })
                | CommandVariant::LoadUpwardDylib(DylibCommand { dylib, .. })
                | CommandVariant::ReexportDylib(DylibCommand { dylib, .. }) => (
                    self.dylib_load(self.image.as_ptr(), *load_command_offset, dylib.name, 0),
                    dylib.name,
                ),

                CommandVariant::LoadWeakDylib(DylibCommand { dylib, .. }) => (
                    self.dylib_load(
                        self.image.as_ptr(),
                        *load_command_offset,
                        dylib.name,
                        libc::RTLD_NOLOAD,
                    ),
                    dylib.name,
                ),

                CommandVariant::LazyLoadDylib(DylibCommand { dylib, .. }) => (
                    self.dylib_load(
                        self.image.as_ptr(),
                        *load_command_offset,
                        dylib.name,
                        libc::RTLD_LAZY,
                    ),
                    dylib.name,
                ),

                _ => continue,
            };

            unsafe {
                self.dylibs.push((
                    self.get_dylib_name_from_offset(*load_command_offset, name)
                        .to_string(),
                    NonNull::new_unchecked(handle),
                ))
            };
        }
    }

    fn dylib_load(
        &self,
        image_base: *const u8,
        load_command_offset: usize,
        name_offset: LcStr,
        flags: i32,
    ) -> *mut libc::c_void {
        unsafe {
            let dylib_name_ptr = image_base
                .add(load_command_offset)
                .add(name_offset as usize) as *const libc::c_char;

            let handle = libc::dlopen(dylib_name_ptr, flags);
            if handle.is_null() {
                panic!("failed to load dylib @ {dylib_name_ptr:?}");
            }

            eprintln!(
                "{:>15}: path: {}: loaded at address {:x?}",
                "init-dylib",
                self.get_dylib_name_from_offset(load_command_offset, name_offset),
                handle
            );
            handle
        }
    }

    unsafe fn get_dylib_name_from_offset(
        &self,
        load_command_offset: usize,
        name_offset: u32,
    ) -> &str {
        unsafe {
            let lc_start = self.image.as_ptr().add(load_command_offset);
            let name_ptr = lc_start.add(name_offset as usize) as *const libc::c_char;

            std::ffi::CStr::from_ptr(name_ptr)
                .to_str()
                .unwrap_or("<invalid utf8>")
        }
    }

    pub fn segments_load_in(&self) {
        self.macho.segments.iter().for_each(
            |Segment {
                 fileoff: image_src_offset,
                 vmaddr: vm_dst_offset,
                 filesize: copy_size,
                 segname: segment_name,
                 ..
             }| {
                unsafe {
                    vm::copy_from_image(
                        self.task,
                        self.image.as_ptr().add(*image_src_offset as usize).addr() as u64,
                        self.vm.as_ptr().add(*vm_dst_offset as usize).addr() as u64,
                        *copy_size as usize,
                    )
                    .unwrap_or_else(|err| panic!("{err}"));
                };

                eprintln!(
                    "{:>15}: name: {}: size: {}KB [image 0x{image_src_offset:010x}] mapped @ [vm 0x{vm_dst_offset:010x}] ~ [vm 0x{:010x}]",
                    "init-segment",
                    String::from_utf8(segment_name.to_vec()).unwrap(),
                    copy_size / 1024,
                    vm_dst_offset + (*copy_size as u64),
                );
            },
        );
    }

    pub fn segments_protection_apply(&self) {
        self.macho.segments.iter().for_each(
            |Segment {
                 segname: segment_name,
                 vmaddr,
                 vmsize,
                 maxprot,
                 initprot,
                 ..
             }| {
                if segment_name_eq(&segment_name, "__PAGEZERO") {
                    return;
                }

                unsafe {
                    let segment_vm_addr = self.vm.add(*vmaddr as usize);

                    [false, true].into_iter().for_each(|max_protection| {
                        vm::memory_protection_set(
                            segment_vm_addr,
                            *vmsize as usize,
                            self.task,
                            *initprot as i32,
                            max_protection as i32,
                        )
                        .unwrap_or_else(|err| panic!("{err:?}"))
                    });

                    eprintln!(
                        "{:>15}: enable protection init={} max={} @ [vm {:x?}] ",
                        "vm-protect",
                        vm_prot_into_string(*initprot as i32),
                        vm_prot_into_string(*maxprot as i32),
                        segment_vm_addr,
                    );

                    self.assert_protection(
                        segment_vm_addr.as_ptr().addr() as u64,
                        *initprot as i32,
                    );
                }
            },
        )
    }

    pub fn assert_protection(&self, addr: u64, prot: i32) {
        match vm::memory_check_protection(self.task, addr, prot) {
            Ok(true) => eprintln!(
                "{:>15}: [vm 0x{addr:x?}] {} is enabled, check ok",
                "vm-check",
                vm_prot_into_string(prot)
            ),
            Ok(false) => panic!(
                "{:>15}: {} is disabed @ 0x{addr:x}, check failed",
                "vm-check",
                vm_prot_into_string(prot)
            ),
            _ => panic!(
                "{:>15}: failed to read memory protections @ 0x{addr:x}",
                "vm-check"
            ),
        };
    }

    pub fn show_imports(&self) {
        dbg!(self.macho.imports().unwrap());
    }

    pub fn jump_to_entry(&self, prog_name: String) {
        let mut bytes = vec![
            CString::new(prog_name)
                .unwrap()
                .as_bytes_with_nul()
                .to_vec(),
        ];

        let argc = bytes.len();
        unsafe {
            let mut envp = *_NSGetEnviron();
            while !(*envp).is_null() {
                bytes.push(CStr::from_ptr(*envp).to_bytes_with_nul().to_vec());
                envp = envp.add(1);
            }

            let argv: Vec<*const u8> = std::iter::once(argc as *const u8)
                .chain(bytes.iter().map(Vec::as_ptr))
                .collect();

            let entry_address = self.vm.add(self.macho.entry as usize);

            let entry_fn = std::mem::transmute::<
                *mut u8,
                extern "C" fn(argc: usize, argv: *const *const u8, envp: *const *const u8),
            >(entry_address.as_ptr());

            self.assert_protection(
                entry_address.as_ptr().addr() as u64,
                (VM_PROT_READ | VM_PROT_EXECUTE) as i32,
            );

            eprintln!(
                "{:>15}: jumping to entry point *{entry_address:x?} ...",
                "done"
            );

            entry_fn(argc, argv.as_ptr(), envp as *const *const u8);
        }
    }
}

pub unsafe fn exec_jit(macho: &MachO<'_>, bytes: &[u8], prog_name: String) -> Result<(), ErrCode> {
    let mut room = Room::new(bytes, macho);

    room.dylibs_load_in();

    room.segments_load_in();

    room.show_imports();
    //room.handle_load_command_dyld_chained_fixups(linkedit, dylib_names);

    room.segments_protection_apply();

    room.jump_to_entry(prog_name);

    Ok(())
}
