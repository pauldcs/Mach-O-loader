use std::ptr::NonNull;

use goblin::mach::{
    Mach, MachO,
    cputype::CPU_TYPE_ARM64,
    load_command::{CommandVariant, DylibCommand, LoadCommand},
};

use crate::mach::{copy_from_image, vm_alloc_self, vm_dealloc_self, vm_protect};

pub mod jumper;
pub mod linker;
pub mod mach;

/// A mach task_t
///
/// This is a wrapper around a mach_port_t.
/// Because we are not in the kernel, a task is represented by
/// this port.
///
/// defined in "mach/mach_types.h"
pub type MachPort = libc::mach_port_t;

#[derive(Debug)]
pub struct Segment {
    /// flags
    flags: u32,

    name: String,

    /// sections within this segment
    sections: Vec<Section>,

    /// file offset of this segment
    offset: usize,

    /// memory address of this segment
    vm_addr: usize,

    /// memory size of this segment
    vm_size: usize,

    /// amount to map from the file,
    /// meaning the size of this segment
    size: usize,

    /// maximum VM protection
    maxprot: i32,

    /// initial VM protection
    initprot: i32,
}

/// Returns the `vm_prot_t` as a human readable string.
pub fn vm_prot_into_string(prot: libc::vm_prot_t) -> String {
    format!(
        "({}{}{})",
        if prot & libc::VM_PROT_READ != 0 {
            "r"
        } else {
            "-"
        },
        if prot & libc::VM_PROT_WRITE != 0 {
            "w"
        } else {
            "-"
        },
        if prot & libc::VM_PROT_EXECUTE != 0 {
            "x"
        } else {
            "-"
        }
    )
}

#[derive(Debug)]
/// Wrapper around a partial section_64 as
/// defined in "mach-o/loader.h"
pub struct Section {
    /// flags (section type and attributes)
    flags: u32,

    name: String,

    /// file offset of this section
    offset: usize,

    /// memory address of this section
    vm_addr: usize,

    /// memory size of this section
    vm_size: usize,

    /// section alignment (power of 2)
    align: usize,
}

#[derive(Debug)]
/// A wrapper around the tasks address space
pub struct Task {
    /// the tasks virtual memory
    pub memory: NonNull<u8>,

    pub dylibs: Vec<(String, u64)>,

    pub symbols: Vec<(String, u64)>,

    /// the tasks virtual memory size
    memory_size: usize,

    /// the segments in the task
    segments: Vec<Segment>,

    /// The entry point (as a virtual memory address), 0 if none
    pub entry_point: usize,
}

impl Drop for Task {
    fn drop(&mut self) {
        vm_dealloc_self(
            self.memory.as_ptr() as libc::mach_vm_address_t,
            self.memory_size,
        );
    }
}

#[inline]
pub fn get_library_ordinal(n_desc: u32) -> u8 {
    ((n_desc >> 8) & 0xff) as u8
}

impl Task {
    /// Creates a task given a pointer and a len
    pub unsafe fn with_pointer(ptr: *const u8, len: usize) -> Self {
        unsafe { task_init(ptr, len) }
    }
}

const RTLD_LAZY: libc::c_int = 0x1;
const RTLD_NOW: libc::c_int = 0x2;
const RTLD_LOCAL: libc::c_int = 0x4;
const RTLD_GLOBAL: libc::c_int = 0x8; // rarely correct to use

impl Task {
    /// Applies memory protection to all segments in the address space.
    pub fn segments_protect(&mut self) {
        self.segments.iter().for_each(|segment| unsafe {
            [false, true].into_iter().for_each(|max| {
                vm_protect(
                    self.memory.offset(segment.vm_addr as isize).as_ptr().addr() as u64,
                    segment.size,
                    max as i32,
                    segment.initprot,
                )
            });
        });
    }

    pub fn symbols_init(&mut self, macho: &MachO) {
        let mut symbols = Vec::<(String, u64)>::new();
        for symbol in macho.symbols() {
            let (name, nlist) = symbol.unwrap();

            /* NLIST_TYPE_LOCAL */
            if nlist.n_type == 1 {
                // remove the trailing '_'
                let lib = get_library_ordinal(nlist.n_desc as u32);
                let (_, lib_handle) = &self.dylibs[(lib - 1) as usize];
                let name = &name[1..name.len()];
                let new_pointer = unsafe {
                    libc::dlsym(*lib_handle as *mut libc::c_void, name.as_ptr() as *const i8)
                };

                if new_pointer.is_null() {
                    panic!("failed to init: {name}");
                }

                symbols.push((name.to_string(), new_pointer.addr() as u64));
            }
        }
        self.symbols = symbols;
    }

    pub fn dylibs_search(&mut self, macho: &MachO, base_addr: &[u8]) {
        let mut dylibs: Vec<(String, u64)> = Vec::new();

        for LoadCommand {
            offset: load_command_offset,
            command,
            ..
        } in &macho.load_commands
        {
            match command {
                CommandVariant::LoadDylib(DylibCommand { dylib, .. })
                | CommandVariant::LoadUpwardDylib(DylibCommand { dylib, .. })
                | CommandVariant::ReexportDylib(DylibCommand { dylib, .. })
                | CommandVariant::LoadWeakDylib(DylibCommand { dylib, .. })
                | CommandVariant::LazyLoadDylib(DylibCommand { dylib, .. }) => {
                    let (flags, _is_weak) = match command {
                        CommandVariant::LazyLoadDylib(_) => (RTLD_LAZY | RTLD_LOCAL, false),
                        CommandVariant::LoadWeakDylib(_) => (RTLD_LAZY | RTLD_LOCAL, true),
                        CommandVariant::ReexportDylib(_) => (RTLD_NOW | RTLD_LOCAL, false),
                        CommandVariant::LoadUpwardDylib(_) => (RTLD_NOW | RTLD_LOCAL, false),
                        CommandVariant::LoadDylib(_) => (RTLD_NOW | RTLD_LOCAL, false),

                        _ => unreachable!(),
                    };

                    let name_offset = dylib.name as usize;
                    let dylib_name_ptr = unsafe {
                        base_addr
                            .as_ptr()
                            .add(*load_command_offset)
                            .add(name_offset) as *const libc::c_char
                    };
                    let name = unsafe {
                        std::ffi::CStr::from_ptr(dylib_name_ptr)
                            .to_str()
                            .unwrap_or("<invalid utf8>")
                    };

                    let handle = unsafe { libc::dlopen(dylib_name_ptr, flags) };
                    if handle.is_null() {
                        panic!("failed to load dylib @ {handle:?}");
                    }

                    dylibs.push((name.to_string(), handle.addr() as u64));
                }

                _ => continue,
            };
        }
        self.dylibs = dylibs;
    }
}

/// Initialize the [`Task`] struct from a pointer and
/// a len.
unsafe fn task_init(ptr: *const u8, len: usize) -> Task {
    if ptr.is_null() {
        panic!("image pointer is null");
    }

    if len == 0 {
        panic!("image is empty");
    }

    if len > 100_000_000 {
        panic!("loaded image is too large");
    }

    let image = unsafe { core::slice::from_raw_parts(ptr, len) };

    match Mach::parse(image) {
        Ok(Mach::Binary(macho)) => {
            // We only support 64-bit mach-o files
            if !macho.is_64 {
                panic!("malforormed mach-o: only 64 bit targets are supported");
            }

            // Initialize the actual task now
            let mut task = task_init_from_macho(&macho, image);

            task.dylibs_search(&macho, image);

            task.symbols_init(&macho);

            task
        }
        Ok(Mach::Fat(multi_arch)) => {
            let arch = multi_arch
                .find_cputype(CPU_TYPE_ARM64)
                .unwrap()
                .expect("loaded image does not contain a usable architecture");

            // extract the CPU_TYPE_ARM64 architecture
            let image = arch.slice(image);

            // Recurse on the extracted architecture
            unsafe { task_init(image.as_ptr(), image.len()) }
        }
        Err(_) => panic!("loaded image pointer is too large"),
    }
}

/// Initializes a task given a parsed MachO.
///
/// `image` is supposed to hold the slice within
/// the initial file that corresponds to this parsed
/// `macho`.
fn task_init_from_macho(macho: &MachO<'_>, image: &[u8]) -> Task {
    // determine the lowest virtual address (min_addr) and the highest
    // virtual address (max_addr) occupied by any segment. The total size is
    // then calculated as the difference.
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

    let entry_point = macho.entry as usize;

    // allocate the tasks address space on our own
    // task
    let memory_size = vm_size;
    let memory = vm_alloc_self(memory_size);

    let segments = macho
        .segments
        .into_iter()
        .map(|seg| {
            let goblin::mach::segment::Segment {
                flags,
                fileoff,
                vmaddr,
                vmsize,
                filesize,
                maxprot,
                initprot,
                ..
            } = *seg;

            let sections = seg
                .sections()
                .expect("no sections found")
                .into_iter()
                .map(|(section, _)| {
                    let goblin::mach::segment::Section {
                        flags,
                        offset,
                        addr,
                        size,
                        align,
                        ..
                    } = section;

                    Section {
                        flags,
                        name: String::from_utf8(section.sectname.to_vec()).unwrap(),
                        offset: offset as usize,
                        vm_addr: addr as usize,
                        vm_size: size as usize,
                        align: align as usize,
                    }
                })
                .collect();

            // Copy the segment data from the Mach-O image into the
            // corresponding location in the address space.
            unsafe {
                copy_from_image(
                    image.as_ptr().add(fileoff as usize).addr() as u64,
                    memory.as_ptr().add(vmaddr as usize).addr() as u64,
                    filesize as usize,
                )
            };

            Segment {
                flags,
                name: String::from_utf8(seg.segname.to_vec()).unwrap(),
                sections,
                offset: fileoff as usize,
                vm_addr: vmaddr as usize,
                vm_size: vmsize as usize,
                size: filesize as usize,
                maxprot: maxprot as i32,
                initprot: initprot as i32,
            }
        })
        .collect::<Vec<_>>();

    Task {
        memory,
        dylibs: Vec::new(),
        symbols: Vec::new(),
        memory_size,
        segments,
        entry_point,
    }
}
