use crate::{
    Section, Segment, Task,
    mach::{S_LAZY_SYMBOL_POINTERS, S_NON_LAZY_SYMBOL_POINTERS, SECTION_TYPE},
};

#[inline]
pub fn get_library_ordinal(n_desc: u32) -> u8 {
    ((n_desc >> 8) & 0xff) as u8
}

#[derive(Debug, Default)]
/// A dynamic linker
pub struct Linker {}
impl Linker {
    pub fn new() -> Self {
        Self {}
    }

    pub fn link_raw(&mut self, task: &mut Task) {
        for Segment {
            name: segname,
            sections,
            ..
        } in &task.segments
        {
            if segname != "__DATA_CONST\0\0\0\0" {
                continue;
            }

            for Section {
                name: sectname,
                flags,
                vm_addr,
                vm_size,
                ..
            } in sections
            {
                if sectname == "__got\0\0\0\0\0\0\0\0\0\0\0" || sectname == "__auth_got\0\0\0\0\0\0"
                {
                    if matches!(
                        *flags as i32 & SECTION_TYPE,
                        S_NON_LAZY_SYMBOL_POINTERS | S_LAZY_SYMBOL_POINTERS
                    ) {
                        unsafe {
                            let ptr = task.memory.add(*vm_addr).as_ptr() as *mut u64;
                            for index in 0..vm_size / 8 {
                                let (_, offset) =
                                    task.symbols.get(index).expect("symbol not found");

                                *ptr.add(index) = *offset;
                            }
                        }
                    } else {
                        panic!("unsupported flags: {}", *flags as i32 & SECTION_TYPE);
                    }
                }
            }
        }
    }
}
