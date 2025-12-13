use crate::{
    Section, Segment, Task,
    mach::{S_LAZY_SYMBOL_POINTERS, S_NON_LAZY_SYMBOL_POINTERS, SECTION_TYPE},
};

#[inline]
pub fn get_library_ordinal(n_desc: u32) -> u8 {
    ((n_desc >> 8) & 0xff) as u8
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
/// Pointer Authenticate au random pointer
///
/// Signs the 'modifier' (`p`) with the key `context`.
/// The instruction computes and inserting a Pointer Authentication Code for `p`
/// and returns it signed.
///
/// https://developer.arm.com/documentation/ddi0602/2025-09/Base-Instructions/PACIA--PACIA1716--PACIASP--PACIAZ--PACIZA--Pointer-Authentication-Code-for-instruction-address--using-key-A-
pub unsafe extern "C" fn pacia(p: u64, context: u64) -> u64 {
    core::arch::naked_asm!("pacia x0, x1", "ret")
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
/// Authenticate a pointer previously signed with `context`
///
/// The pointer that is authenticated must have been previously signed.
/// If the authentication passes, the upper bits of the address are restored and
/// the pointer is returned.
///
/// https://developer.arm.com/documentation/ddi0602/2025-09/Base-Instructions/AUTIA--AUTIA1716--AUTIASP--AUTIAZ--AUTIZA--Authenticate-instruction-address--using-key-A-
pub unsafe extern "C" fn autia(p: u64, context: u64) -> u64 {
    core::arch::naked_asm!("autia x0, x1", "ret")
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
