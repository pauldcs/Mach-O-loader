use core::slice;

use goblin::mach::{Mach, cputype::CPU_TYPE_ARM64};

mod room;
mod utilities;
mod vm;

#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ErrCode {
    OK = 0,
    ENULL = -1,
    ENOLEN = -2,
    ESIZE = -3,
    EINVAL = -4,
    EMEM = -5,
    EARCH = -6,
    EMEMALLOC = -7,
}

#[derive(Debug, Copy, Clone)]
struct UnsafeView {
    ptr: *const u8,
    len: usize,
}

impl UnsafeView {
    fn new(ptr: *const u8, len: usize) -> Self {
        Self { ptr, len }
    }

    fn is_null(&self) -> bool {
        self.ptr.is_null()
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    unsafe fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
}

#[unsafe(no_mangle)]
/// Main entry point for the loader.
///
/// # Safety
/// Nothing is safe
pub extern "C" fn execvm(ptr: *const u8, len: usize, name: *const u8, name_len: usize) -> ErrCode {
    let unsafe_view = UnsafeView::new(ptr, len);

    if unsafe_view.is_null() {
        return ErrCode::ENULL;
    }

    if unsafe_view.is_empty() {
        return ErrCode::ENOLEN;
    }

    if len > 100_000_000 {
        return ErrCode::ESIZE;
    }

    let mut __bytes__ = unsafe { unsafe_view.as_slice() };

    match Mach::parse(__bytes__) {
        Ok(Mach::Binary(macho)) => unsafe {
            let name = match str::from_utf8(slice::from_raw_parts(name, name_len)) {
                Ok(v) => v.to_string(),
                Err(_) => panic!("Invalid UTF-8"),
            };

            room::exec_jit(&macho, __bytes__, name)
                .err()
                .unwrap_or(ErrCode::OK)
        },
        Ok(Mach::Fat(multi_arch)) => multi_arch
            .find_cputype(CPU_TYPE_ARM64)
            .ok()
            .and_then(|arch| arch)
            .map(|arch| {
                let slice = arch.slice(__bytes__);
                execvm(slice.as_ptr(), slice.len(), name, name_len)
            })
            .unwrap_or(ErrCode::EARCH),
        Err(_) => ErrCode::EINVAL,
    }
}
