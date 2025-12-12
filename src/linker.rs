use core::slice;
use std::{collections::HashMap, mem};

use crate::{
    Section, Segment, Task,
    mach::{S_LAZY_SYMBOL_POINTERS, S_NON_LAZY_SYMBOL_POINTERS, SECTION_TYPE},
};

#[derive(Debug, Default)]
/// A dynamic linker
pub struct Linker {}
impl Linker {
    pub fn new() -> Self {
        Self {}
    }

    pub fn link_raw(&mut self, task: &mut Task) {
        let mut rebinds = HashMap::<u64, u64>::new();
        for Segment { name, sections, .. } in &task.segments {
            if name != "__DATA_CONST\0\0\0\0" {
                continue;
            }

            for Section {
                name,
                flags,
                vm_addr,
                vm_size,
                ..
            } in sections
            {
                if name == "__got\0\0\0\0\0\0\0\0\0\0\0" {
                    if !matches!(
                        *flags as i32 & SECTION_TYPE,
                        S_NON_LAZY_SYMBOL_POINTERS | S_LAZY_SYMBOL_POINTERS
                    ) {
                        continue;
                    }

                    unsafe {
                        for _ in 0..vm_size / 8 {
                            rebinds
                                .insert(task.memory.as_ptr().add(*vm_addr).addr() as u64, 0xffff);
                        }
                    }
                }
            }
        }

        let dylibs = mem::take(&mut task.dylibs);
        for dylib in dylibs {
            dbg!(dylib);
        }

        for rebind in rebinds {
            dbg!(rebind);
        }
    }
}

pub fn read_ptr(data: &[u8]) -> u64 {
    let ptr = u64::from_le_bytes(data.try_into().unwrap());

    // On arm64, high nibble of pointers can have extra bits
    if ptr & 0xF000000000000000 != 0 {
        return ptr & 0x0FFFFFFFFFFFFFFF;
    }
    ptr
}

// pub fn dylib_load(
//     image_base: *const u8,
//     load_command_offset: usize,
//     name_offset: u32,
//     flags: i32,
// ) -> *mut libc::c_void {
//     unsafe {
//         let dylib_name_ptr = image_base
//             .add(load_command_offset)
//             .add(name_offset as usize) as *const libc::c_char;

//         let handle = libc::dlopen(dylib_name_ptr, flags);
//         if handle.is_null() {
//             panic!("failed to load dylib @ {dylib_name_ptr:?}");
//         }

//         handle
//     }
// }
