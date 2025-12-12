use std::ptr::NonNull;

use libc::{mach_error_string, mach_port_t};

#[allow(nonstandard_style)]
pub type kern_return_t = libc::c_int;

#[allow(nonstandard_style)]
pub type mach_port_name_t = libc::natural_t;

#[allow(nonstandard_style)]
pub type task_t = mach_port_name_t;

const KERN_SUCCESS: kern_return_t = libc::KERN_SUCCESS;

/// Abort everything
///
/// Panics with a descriptive Mach kernel error message for the given `kern_return_t`.
/// Falls back to a placeholder if no message or invalid UTF-8 is returned.
fn panic_kr_error(kern_return: kern_return_t) -> ! {
    let msg = unsafe {
        let ptr = mach_error_string(kern_return);
        if ptr.is_null() {
            panic!("panic_kr_error: {kern_return}: no error message");
        }

        std::ffi::CStr::from_ptr(ptr)
            .to_str()
            .unwrap_or("<invalid utf8>")
    };

    panic!("panic_kr_error: {kern_return}: {msg}");
}

unsafe extern "C" {
    /// The task port of the current task
    static mach_task_self_: mach_port_t;

    /// Get the task port for another "process", named by its
    /// process ID on the same host as "target_task".
    ///
    /// Only permitted to privileged processes, or processes
    /// with the same user ID.
    ///
    /// Note: if pid == 0, an error is return no matter who is calling.
    pub fn _task_for_pid(target_tport: task_t, pid: libc::c_int, tn: *mut task_t) -> kern_return_t;
}

//	Allocate new VM region anywhere it would fit in the address space.
const VM_FLAGS_ANYWHERE: i32 = 0x00000001;

unsafe extern "C" {
    /// Allocate a region of virtual memory.
    /// As opposed to `vm_allocate`, this function allocates 64-bit memory
    pub fn mach_vm_allocate(
        target: task_t,
        address: *mut libc::mach_vm_address_t,
        size: libc::mach_vm_size_t,
        flags: libc::c_int,
    ) -> kern_return_t;

    /// Deallocate a region of virtual memory.
    /// As opposed to `vm_deallocate`, this function works with 64-bit addresses.
    pub fn mach_vm_deallocate(
        target: task_t,
        address: libc::mach_vm_address_t,
        size: libc::mach_vm_size_t,
    ) -> kern_return_t;

    /// Copies data into the tasks address space
    /// As opposed to `vm_deallocate`, this function works with 64-bit addresses.
    pub fn mach_vm_write(
        target: task_t,
        address: libc::mach_vm_address_t,
        data_u: libc::mach_vm_address_t,
        size: libc::mach_vm_size_t,
    ) -> kern_return_t;

    /// Change memory protection for a region of virtual memory.
    /// As opposed to `vm_protect`, this function works with 64-bit addresses
    pub fn mach_vm_protect(
        task: mach_port_name_t,
        address: libc::mach_vm_address_t,
        size: libc::mach_vm_size_t,
        set_maximum: libc::boolean_t,
        new_protection: libc::vm_prot_t,
    ) -> kern_return_t;
}

#[inline]
/// Returns the current tasks port
///
/// SAFETY? not sure but you can use a thread lock externally
fn mach_task_self() -> mach_port_t {
    unsafe { mach_task_self_ }
}

// pub unsafe fn get_own_task() -> Result<task_t, kern_return_t> {
//     let mut task: task_t = 0;

//     unsafe {
//         match task_for_pid(mach_task_self(), std::process::id() as i32, &mut task) {
//             KERN_SUCCESS => Ok(task),
//             kern_return => Err(kern_return),
//         }
//     }
// }

/// The flags field of a section structure is separated into two parts a section
/// type and section attributes.  The section types are mutually exclusive (it
/// can only have one type) but the section attributes are not (it may have more
/// than one attribute).
pub const SECTION_TYPE: i32 = 0x000000ff; // 256 section types
pub const SECTION_ATTRIBUTES: u32 = 0xffffff00; // 24 section attributes

// For the two types of symbol pointers sections and the symbol stubs section
// they have indirect symbol table entries.  For each of the entries in the
// section the indirect symbol table entries, in corresponding order in the
// indirect symbol table, start at the index stored in the reserved1 field
// of the section structure.  Since the indirect symbol table entries
// correspond to the entries in the section the number of indirect symbol table
// entries is inferred from the size of the section divided by the size of the
// entries in the section.  For symbol pointers sections the size of the entries
// in the section is 4 bytes and for symbol stubs sections the byte size of the
// stubs is stored in the reserved2 field of the section structure.
pub const S_NON_LAZY_SYMBOL_POINTERS: i32 = 0x6; // section with only non-lazy  symbol pointers
pub const S_LAZY_SYMBOL_POINTERS: i32 = 0x7; // section with only lazy symbol

/// Internal function that calls mach_vm_allocate from
/// "mach/mach_vm.c"
unsafe fn vm_alloc_internal(size: usize) -> Result<NonNull<u8>, kern_return_t> {
    let mut addr = 0;
    let kern_return = unsafe {
        mach_vm_allocate(
            mach_task_self(),
            &mut addr,
            size as libc::mach_vm_size_t,
            VM_FLAGS_ANYWHERE,
        )
    };
    match kern_return {
        KERN_SUCCESS => NonNull::new(addr as *mut u8).ok_or_else(|| panic!("ptr is null")),
        _ => Err(kern_return),
    }
}

/// Internal function that calls mach_vm_deallocate from
/// "mach/mach_vm.c"
unsafe fn vm_dealloc_internal(
    address: libc::mach_vm_address_t,
    size: usize,
) -> Result<(), kern_return_t> {
    let kern_return =
        unsafe { mach_vm_deallocate(mach_task_self(), address, size as libc::mach_vm_size_t) };

    match kern_return {
        KERN_SUCCESS => Ok(()),
        _ => Err(kern_return),
    }
}

/// Internal function that calls mach_vm_write from
/// "mach/mach_vm.c"
unsafe fn vm_copy_overwrite_internal(
    src: libc::mach_vm_address_t,
    dst: libc::mach_vm_address_t,
    count: usize,
) -> Result<(), kern_return_t> {
    let kern_return =
        unsafe { mach_vm_write(mach_task_self(), dst, src, count as libc::mach_vm_size_t) };

    match kern_return {
        KERN_SUCCESS => Ok(()),
        _ => Err(kern_return),
    }
}

/// Change memory protection for a region of virtual memory.
/// As opposed to `vm_protect`, this function works with 64-bit addresses.
unsafe fn vm_protect_internal(
    ptr: libc::mach_vm_address_t,
    size: libc::mach_vm_size_t,
    set_maximum: libc::boolean_t,
    protection: libc::vm_prot_t,
) -> Result<(), kern_return_t> {
    unsafe {
        let kern_return = mach_vm_protect(mach_task_self(), ptr, size, set_maximum, protection);
        match kern_return {
            KERN_SUCCESS => Ok(()),
            kern_return => Err(kern_return),
        }
    }
}

/// Allocates memory on the current task address space
///
/// # Panics
///
/// if an error happens, this function panics
pub fn vm_alloc_self(size: usize) -> NonNull<u8> {
    unsafe { vm_alloc_internal(size).unwrap_or_else(|kern_error| panic_kr_error(kern_error)) }
}

/// Deallocates memory on the current task address space
///
/// # Panics
///
/// If an error happens, this function panics.
pub fn vm_dealloc_self(address: libc::mach_vm_address_t, size: usize) {
    unsafe {
        vm_dealloc_internal(address, size as libc::vm_size_t)
            .unwrap_or_else(|kern_error| panic_kr_error(kern_error))
    }
}

/// Copies `count` bytes from source into `dst`
pub fn copy_from_image(src: libc::mach_vm_address_t, dst: libc::mach_vm_address_t, count: usize) {
    unsafe {
        vm_copy_overwrite_internal(src, dst, count)
            .unwrap_or_else(|kern_error| panic_kr_error(kern_error))
    }
}

/// Applies the protection to `ptr` -> `size`
pub fn vm_protect(
    ptr: libc::mach_vm_address_t,
    size: usize,
    set_maximum: libc::boolean_t,
    protection: libc::vm_prot_t,
) {
    unsafe {
        vm_protect_internal(ptr, size as u64, set_maximum, protection)
            .unwrap_or_else(|kern_error| panic_kr_error(kern_error))
    }
}
