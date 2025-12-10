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
