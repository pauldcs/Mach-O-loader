use core::fmt;
use std::{collections::HashMap, ptr::NonNull};

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
/// This is a wrapper around the C.
/// Because we are not in the kernel, a task is represented by
/// this port.
///
/// defined in "mach/mach_types.h"
pub type MachPort = libc::mach_port_t;

/// A segment, made up of zero or more sections. This
/// partially wraps the segment_command_64 as defined in
/// "mach-o/loader.h"
///
/// The segments indicates mappings in the task's address space.
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

impl fmt::Debug for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Segment")
            .field("flags", &format_args!("0x{:08x}", self.flags))
            .field("name", &format_args!("'{}'", self.name))
            .field("offset", &format_args!("0x{:x}", self.offset))
            .field("vm_addr", &format_args!("0x{:x}", self.vm_addr))
            .field(
                "vm_size",
                &format_args!("0x{:x} ({} bytes)", self.vm_size, self.vm_size),
            )
            .field(
                "size",
                &format_args!("0x{:x} ({} bytes)", self.size, self.size),
            )
            .field("maxprot", &vm_prot_into_string(self.maxprot))
            .field("initprot", &vm_prot_into_string(self.initprot))
            .field("sections", &self.sections)
            .finish()
    }
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

impl fmt::Debug for Section {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Section")
            .field("flags", &format_args!("0x{:08x}", self.flags))
            .field("name", &format_args!("'{}'", self.name))
            .field("offset", &format_args!("0x{:x}", self.offset))
            .field("vm_addr", &format_args!("0x{:x}", self.vm_addr))
            .field(
                "vm_size",
                &format_args!("0x{:x} ({} bytes)", self.vm_size, self.vm_size),
            )
            .field(
                "align",
                &format_args!("2^{} ({} bytes)", self.align, 1usize << self.align),
            )
            .finish()
    }
}

/// A wrapper around the tasks address space
pub struct Task {
    /// the tasks virtual memory
    pub memory: NonNull<u8>,

    pub dylibs: HashMap<String, u64>,

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

impl fmt::Debug for Task {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("Task");

        debug.field("memory", &format_args!("{:p}", self.memory.as_ptr()));
        debug.field("segments", &self.segments);
        debug.field("dylibs", &self.dylibs);

        if self.entry_point == 0 {
            debug.field("entry_point", &"None");
        } else {
            debug.field("entry_point", &format_args!("0x{:x}", self.entry_point));
        }

        debug.finish()
    }
}

impl Task {
    /// Creates a task given a pointer and a len
    ///
    /// # Safety
    /// the caller must make sure ptr and len are valid for
    /// the image loaded from the file
    pub unsafe fn with_pointer(ptr: *const u8, len: usize) -> Self {
        unsafe { task_init(ptr, len) }
    }
}

impl Task {
    /// Applies memory protection to all segments in the address space.
    ///
    /// Iterates over each segment and calls `vm_protect` twice:
    /// once for the current protection and once for the maximum protection,
    /// setting the segment's initial protection flags.
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

    pub fn dylibs_search(&mut self, macho: &MachO, base_addr: &[u8]) /*-> *mut libc::c_void*/
    {
        let mut dylibs: HashMap<String, u64> = HashMap::new();

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

                    dylibs.insert(name.to_string(), dylib_name_ptr.addr() as u64);
                }

                _ => continue,
            };
        }
        self.dylibs = dylibs;
    }
}

/// Initialize the [`Task`] struct from a pointer and
/// a len.
///
/// # Panics
///
/// If the mach o pointed to is malformed this function
/// panics
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
    // Compute the total virtual memory size spanned by all Mach-O segments.
    //
    // We first determine the lowest virtual address (min_addr) and the highest
    // virtual address (max_addr) occupied by any segment. The total size is
    // then calculated as the difference.
    //
    // If there are no segments, both min_addr and max_addr default to 0, and
    // saturating_sub ensures vm_size is 0 rather than underflowing.
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
            // This is effectively a direct memcpy from the original
            // image into the mapped memory region for the segment.
            // No memory protections are applied by this function. it
            // simply writes the raw data to the correct offsets.
            // Memory protections must be set separately after this
            // step before the segment can be safely executed or accessed.
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
        dylibs: HashMap::new(),
        memory_size,
        segments,
        entry_point,
    }
}
