use crate::{
    Section, Segment, Task,
    mach::{S_LAZY_SYMBOL_POINTERS, S_NON_LAZY_SYMBOL_POINTERS, SECTION_TYPE},
};

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

// unsafe extern "C" {
//     pub fn pacia(p: u64, context: u64) -> u64;
//     pub fn autia(p: u64, context: u64) -> u64;
// }

#[cfg(test)]
mod tests {
    #[test]
    pub fn test_pac() {
        unsafe {
            let ptr: u64 = 0x0000_1234_5678_9abc;
            let ctx_ok: u64 = 666;
            let ctx_bad: u64 = 777;

            let signed = crate::linker::pacia(ptr, ctx_ok);
            let auth_ok = crate::linker::autia(signed, ctx_ok);
            let auth_bad = crate::linker::autia(signed, ctx_bad);

            assert!(signed != ptr);
            assert!(auth_ok == ptr);
            assert!(auth_bad != ptr);
        }
    }
}

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
                let (is_got, is_auth_got) = (
                    sectname == "__got\0\0\0\0\0\0\0\0\0\0\0",
                    sectname == "__auth_got\0\0\0\0\0\0",
                );

                if is_got || is_auth_got {
                    if matches!(
                        *flags as i32 & SECTION_TYPE,
                        S_NON_LAZY_SYMBOL_POINTERS | S_LAZY_SYMBOL_POINTERS
                    ) {
                        unsafe {
                            let sect_ptr = task.memory.add(*vm_addr).as_ptr() as *mut u64;
                            for index in 0..vm_size / 8 {
                                let linked_sym_offset = task
                                    .symbols
                                    .get(index)
                                    .map(|(_, symoff)| symoff.to_owned())
                                    .expect("symbol not found");

                                let dst_ptr = sect_ptr.add(index);

                                if is_auth_got {
                                    // https://developer.arm.com/documentation/ddi0602/2025-09/Base-Instructions/BRAA--BRAAZ--BRAB--BRABZ--Branch-to-register--with-pointer-authentication-
                                    //
                                    // Jumps to an authenticated pointer seems to be done through a wrapper in __auth_stubs.
                                    // It doesn't directly jumps to these pointers in the offset table, it jumps to a wrapper which
                                    // authenticates that pointer first.
                                    //
                                    // This is an example of a wrapper (in this case ___assert_rtn)
                                    //
                                    // First it loads the address where that signed pointer is into x17.
                                    // The pointer at that address has to be signed.
                                    //
                                    //     adrp    x17, 0x100008000 // offset table
                                    //     add     x17, x17, #0x28  // index within the table
                                    //
                                    // Then it loads the actual pointer itself into x16.
                                    //
                                    //     ldr     x16, [x17]
                                    //
                                    // Then it does an authenticated jump to that address. It does so by
                                    // branching to the (authenticated) pointer using the location of it as
                                    // modifier.
                                    //
                                    //     braa    x16, x17 // jumps or faults if no match

                                    // linked_sym_offset =
                                    //     pacia(linked_sym_offset, dst_ptr.addr() as u64);
                                }

                                *dst_ptr = linked_sym_offset;
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
