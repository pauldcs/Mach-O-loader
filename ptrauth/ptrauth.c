#include "ptrauth.h"

/// Pointer Authenticate au random pointer
///
/// Signs the 'modifier' (`p`) with the key `context`.
/// The instruction computes and inserting a Pointer Authentication Code for `p`
/// and returns it signed.
///
/// https://developer.arm.com/documentation/ddi0602/2025-09/Base-Instructions/PACIA--PACIA1716--PACIASP--PACIAZ--PACIZA--Pointer-Authentication-Code-for-instruction-address--using-key-A-
__attribute__((naked, weak)) uint64_t pacia(uint64_t p, uint64_t context) {
	__asm__(
		"pacia x0, x1\n"
		"ret"
	);
}

/// Authenticate a pointer previously signed with `context`
///
/// The pointer that is authenticated must have been previously signed.
/// If the authentication passes, the upper bits of the address are restored and
/// the pointer is returned.
///
/// https://developer.arm.com/documentation/ddi0602/2025-09/Base-Instructions/AUTIA--AUTIA1716--AUTIASP--AUTIAZ--AUTIZA--Authenticate-instruction-address--using-key-A-
__attribute__((naked, weak)) uint64_t autia(uint64_t p, uint64_t context) {
	__asm__(
		"autia x0, x1\n"
		"ret"
	);
}