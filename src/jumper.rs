use std::{ffi, ptr::NonNull};

/// Jumps and transfers control flow to the offset `entry_point`
/// from memory.
pub fn jumper(memory: NonNull<u8>, entry_point: usize) -> ! {
    // convert program name to null-terminated string
    let name = ffi::CString::new("dummy_name").unwrap();

    // initialize argument vector with program name
    let mut argv = vec![name.as_bytes_with_nul()];

    let argc = argv.len();
    unsafe {
        // get environment variables from libc
        let mut envp = *libc::_NSGetEnviron();

        while !(*envp).is_null() {
            // push each environment string to argv with null terminator
            argv.push(ffi::CStr::from_ptr(*envp).to_bytes_with_nul());
            envp = envp.add(1);
        }

        // get the entry point pointer in memory
        let entry_address = memory.add(entry_point).as_ptr();

        // cast it to a main function
        let entry_fn = std::mem::transmute::<
            *mut u8,
            extern "C" fn(argc: usize, argv: *const *const u8, envp: *const *const u8),
        >(entry_address);

        // call it
        entry_fn(
            argc,
            argv.as_ptr() as *const *const u8,
            envp as *const *const u8,
        );

        // completed successfully
        std::process::exit(0)
    }
}
