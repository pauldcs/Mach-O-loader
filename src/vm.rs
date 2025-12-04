use libc::mach_vm_address_t;
use mach_sys::{
    kern_return, mach_types,
    vm_region::{VM_REGION_BASIC_INFO_64, vm_region_basic_info_64, vm_region_info_t},
    vm_types,
};

/// Error type for VM operations
#[derive(Debug)]
pub enum VmError {
    AllocationFailed(kern_return::kern_return_t),
    MemWrite(kern_return::kern_return_t),
    DeallocationFailed(kern_return::kern_return_t),
    TaskForPidFailed(kern_return::kern_return_t),
    ProtectFailed(kern_return::kern_return_t),
    GetProtectionFailed(kern_return::kern_return_t),
}

impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmError::AllocationFailed(code) => {
                write!(f, "VM allocation failed with code: {}", code)
            }
            VmError::DeallocationFailed(code) => {
                write!(f, "VM deallocation failed with code: {}", code)
            }
            VmError::MemWrite(code) => {
                write!(f, "memory write error: {}", code)
            }
            VmError::TaskForPidFailed(code) => write!(f, "task_for_pid failed with code: {}", code),
            VmError::ProtectFailed(code) => write!(f, "VM protect failed with code: {}", code),
            VmError::GetProtectionFailed(code) => write!(f, "get VM protection failed: {}", code),
        }
    }
}

pub unsafe fn self_task_get() -> Result<mach_types::task_t, VmError> {
    unsafe {
        let mut task: mach_types::task_t = 0;
        match mach_sys::traps::task_for_pid(
            mach_sys::traps::mach_task_self(),
            std::process::id() as i32,
            &mut task,
        ) {
            mach_sys::kern_return::KERN_SUCCESS => Ok(task),
            kern_return => Err(VmError::TaskForPidFailed(kern_return)),
        }
    }
}

pub unsafe fn copy_from_image(
    task: mach_types::task_t,
    src: vm_types::mach_vm_address_t,
    dst: vm_types::mach_vm_address_t,
    count: usize,
) -> Result<(), VmError> {
    unsafe {
        let kern_return =
            mach_sys::vm::mach_vm_write(task, dst, src.try_into().unwrap(), count as u32);
        match kern_return {
            mach_sys::kern_return::KERN_SUCCESS => Ok(()),
            _ => Err(VmError::MemWrite(kern_return)),
        }
    }
}

pub unsafe fn memory_alloc(
    size: usize,
    task: mach_types::task_t,
) -> Result<std::ptr::NonNull<u8>, VmError> {
    let mut addr = 0;
    let kern_return = unsafe {
        mach_sys::vm::mach_vm_allocate(
            task,
            &mut addr,
            size as vm_types::mach_vm_size_t,
            mach_sys::vm_statistics::VM_FLAGS_ANYWHERE,
        )
    };
    match kern_return {
        mach_sys::kern_return::KERN_SUCCESS => {
            std::ptr::NonNull::new(addr as *mut u8).ok_or(VmError::AllocationFailed(kern_return))
        }
        _ => Err(VmError::AllocationFailed(kern_return)),
    }
}

pub unsafe fn memory_dealloc(
    ptr: std::ptr::NonNull<u8>,
    size: usize,
    task: mach_types::task_t,
) -> Result<(), VmError> {
    let kern_return = unsafe {
        mach_sys::vm::mach_vm_deallocate(
            task,
            ptr.as_ptr().addr() as u64,
            size as vm_types::mach_vm_size_t,
        )
    };

    match kern_return {
        mach_sys::kern_return::KERN_SUCCESS => Ok(()),
        _ => Err(VmError::DeallocationFailed(kern_return)),
    }
}

pub fn memory_check_protection(
    task: mach_types::task_t,
    addr: u64,
    prot: i32,
) -> Result<bool, VmError> {
    unsafe {
        let mut size = 0x10;
        let mut object_name = 0;
        #[allow(clippy::fn_to_numeric_cast)]
        let mut address = addr as mach_vm_address_t;
        let mut info: vm_region_basic_info_64 = std::mem::zeroed();
        let mut info_size = vm_region_basic_info_64::count();

        let kern_return = mach_sys::vm::mach_vm_region(
            task,
            &mut address,
            &mut size,
            VM_REGION_BASIC_INFO_64,
            (&mut info as *mut _) as vm_region_info_t,
            &mut info_size,
            &mut object_name,
        );

        match kern_return {
            mach_sys::kern_return::KERN_SUCCESS => Ok(info.protection == prot),
            _ => Err(VmError::GetProtectionFailed(kern_return)),
        }
    }
}

pub unsafe fn memory_protection_set(
    ptr: std::ptr::NonNull<u8>,
    size: usize,
    task: mach_types::task_t,
    protection: mach_sys::vm_prot::vm_prot_t,
    max_protection: mach_sys::vm_prot::vm_prot_t,
) -> Result<(), VmError> {
    unsafe {
        let kern_return = mach_sys::vm::mach_vm_protect(
            task,
            ptr.as_ptr() as vm_types::mach_vm_address_t,
            size as vm_types::mach_vm_size_t,
            max_protection,
            protection,
        );
        match kern_return {
            mach_sys::kern_return::KERN_SUCCESS => Ok(()),
            _ => Err(VmError::ProtectFailed(kern_return)),
        }
    }
}
