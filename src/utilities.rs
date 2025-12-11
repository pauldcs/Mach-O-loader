use mach_sys::vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE, vm_prot_t};

pub fn segment_name_eq<T: AsRef<[u8]>>(segname: &[u8; 16], name: T) -> bool {
    segname.as_ref().starts_with(name.as_ref())
}

pub fn vm_prot_into_string(prot: vm_prot_t) -> String {
    let is_r = if prot & VM_PROT_READ != 0 { "r" } else { "-" };
    let is_w = if prot & VM_PROT_WRITE != 0 { "w" } else { "-" };
    let is_x = if prot & VM_PROT_EXECUTE != 0 {
        "x"
    } else {
        "-"
    };

    format!("({is_r}{is_w}{is_x})")
}

pub fn read_ptr(is_64: bool, data: &[u8], offset: usize) -> u64 {
    let ptr = if is_64 {
        u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
    } else {
        u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as u64
    };

    // On arm64, high nibble of pointers can have extra bits
    if ptr & 0xF000000000000000 != 0 {
        return ptr & 0x0FFFFFFFFFFFFFFF;
    }
    ptr
}
