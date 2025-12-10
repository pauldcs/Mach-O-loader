use core::slice;

use goblin::mach::{Mach, cputype::CPU_TYPE_ARM64};

mod room;
mod utilities;
mod vm;

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
/// Main entry point for the loader.
///
/// # Safety
///
/// Nothing is safe
pub extern "C" fn execvm(ptr: *const u8, len: usize, name: *const u8, name_len: usize) -> ! {
    if ptr.is_null() {
        panic!("image pointer is null");
    }

    if len == 0 {
        panic!("image is empty");
    }

    if len > 100_000_000 {
        panic!("loaded image is too large");
    }

    let loaded_image = unsafe { core::slice::from_raw_parts(ptr, len) };

    match Mach::parse(loaded_image) {
        Ok(Mach::Binary(macho)) => unsafe {
            let name = str::from_utf8(slice::from_raw_parts(name, name_len))
                .map_or_else(|err| panic!("UTF-8 error: {err}"), str::to_string);

            room::exec_jit(&macho, loaded_image, name)
        },
        Ok(Mach::Fat(multi_arch)) => {
            let arch = multi_arch
                .find_cputype(CPU_TYPE_ARM64)
                .unwrap()
                .expect("loaded image does not contain a usable architecture");

            let loaded_image = arch.slice(loaded_image);
            execvm(loaded_image.as_ptr(), loaded_image.len(), name, name_len);
        }
        Err(_) => panic!("loaded image pointer is too large"),
    }
}
