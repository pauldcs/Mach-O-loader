use std::{
    ffi::{CStr, CString},
    ptr::NonNull,
};

use goblin::mach::{
    MachO,
    constants::{S_LAZY_SYMBOL_POINTERS, S_NON_LAZY_SYMBOL_POINTERS, SECTION_TYPE},
    load_command::{CommandVariant, DylibCommand, LcStr, LoadCommand},
    segment::Segment,
    symbols::N_UNDF,
};
use libc::_NSGetEnviron;
use mach_sys::{
    mach_types::task_t,
    vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ},
};

use crate::{
    utilities::{read_ptr, segment_name_eq, vm_prot_into_string},
    vm,
};

#[inline]
pub fn get_library_ordinal(n_desc: u32) -> u8 {
    ((n_desc >> 8) & 0xff) as u8
}

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
                "{:>15}: {}: loaded at address {:x?}",
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

    pub fn segments_initialize(&self) {
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
                    "{:>15}: {}: {}KB [image 0x{image_src_offset:010x}] mapped @ [vm 0x{vm_dst_offset:010x}] ~ [vm 0x{:010x}]",
                    "init-segment",
                    String::from_utf8(segment_name.to_vec()).unwrap(),
                    copy_size / 1024,
                    vm_dst_offset + *copy_size,
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
                if segment_name_eq(segment_name, "__PAGEZERO") {
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
                        "{:>15}: enable protection {}/{} @ [vm {:x?}] ",
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

    pub unsafe fn rebind_global_offset_table(&mut self) {
        for segment in &self.macho.segments {
            if !segment_name_eq(&segment.segname, "__DATA_CONST") {
                continue;
            }

            for (_, (section, data)) in segment.sections().unwrap().iter().enumerate() {
                if !segment_name_eq(&section.sectname, "__got") {
                    continue;
                }

                match section.flags & SECTION_TYPE {
                    S_NON_LAZY_SYMBOL_POINTERS | S_LAZY_SYMBOL_POINTERS => {
                        let entry_size = if self.macho.is_64 { 8 } else { 4 };
                        for nth_entry in 0..data.len() / entry_size {
                            let ptr_value =
                                read_ptr(self.macho.is_64, data, nth_entry * entry_size);

                            let (symname, nlist) = self
                                .macho
                                .symbols()
                                .find(|s| matches!(s, Ok((_, nlist)) if nlist.n_value == ptr_value))
                                .expect(
                                    "malformed Mach-O: no symbol found (referenced by {ptr_value})",
                                )
                                .expect("malformed Mach-O");

                            match nlist.get_type() {
                                N_UNDF => {
                                    let lib_index = get_library_ordinal(nlist.n_desc as u32);
                                    let (lib_name, lib_handle) =
                                        &self.dylibs[(lib_index - 1) as usize];

                                    let cname =
                                        std::str::from_utf8(&symname[1..symname.len()].as_bytes())
                                            .unwrap();

                                    let new_pointer = unsafe {
                                        libc::dlsym(
                                            lib_handle.as_ptr(),
                                            cname.as_ptr() as *const i8,
                                        )
                                    };

                                    let offset_pointer = unsafe {
                                        self.vm.offset(section.addr as isize).as_ptr() as *mut u64
                                    };

                                    unsafe { *offset_pointer = new_pointer as u64 };

                                    eprintln!(
                                        "{:>15}: {lib_name}: {cname:?} mapped @ {new_pointer:x?} to {offset_pointer:x?}",
                                        "dylink",
                                    );
                                }
                                _ => {
                                    panic!(
                                        "malformed Mach-O: unsupported N_UNDF::n_value ({}) on symbol {symname} @ {ptr_value}",
                                        nlist.n_value
                                    )
                                }
                            }
                        }
                    }
                    _ => (),
                }
            }
        }
    }

    pub fn assert_protection(&self, addr: u64, prot: i32) {
        match vm::memory_check_protection(self.task, addr, prot) {
            Ok(true) => eprintln!(
                "{:>15}: [vm 0x{addr:x?}] {} is enabled",
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

    pub fn jump_to_entry(&self, prog_name: String) -> ! {
        let mut program_arguments = vec![
            CString::new(prog_name)
                .unwrap()
                .as_bytes_with_nul()
                .to_vec(),
        ];

        let argc = program_arguments.len();
        unsafe {
            let mut envp = *_NSGetEnviron();
            while !(*envp).is_null() {
                program_arguments.push(CStr::from_ptr(*envp).to_bytes_with_nul().to_vec());
                envp = envp.add(1);
            }

            let argv: Vec<*const u8> = std::iter::once(argc as *const u8)
                .chain(program_arguments.iter().map(Vec::as_ptr))
                .collect();

            let entry_address = self.vm.add(self.macho.entry as usize).as_ptr();

            let entry_fn = std::mem::transmute::<
                *mut u8,
                extern "C" fn(argc: usize, argv: *const *const u8, envp: *const *const u8),
            >(entry_address);

            self.assert_protection(entry_address.addr() as u64, VM_PROT_READ | VM_PROT_EXECUTE);

            // loop {
            //     if argc == 0 {
            //         break;
            //     }
            // }

            eprintln!("{:>15}: jumping to {entry_address:x?} ...", "done");

            entry_fn(argc, argv.as_ptr(), envp as *const *const u8);

            std::process::exit(0)
        }
    }
}

pub unsafe fn exec_jit(macho: &MachO<'_>, image: &[u8], name: String) -> ! {
    let mut exec_room = Room::new(image, macho);

    exec_room.dylibs_load_in();

    exec_room.segments_initialize();

    exec_room.rebind_global_offset_table();

    exec_room.segments_protection_apply();

    exec_room.jump_to_entry(name);
}
