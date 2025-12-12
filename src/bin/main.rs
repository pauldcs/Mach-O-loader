use std::fs;

use loader::{Task, jumper::jumper, linker::Linker};

fn main() {
    let bin = "./binaries/hello_world_fprintf/hello_world";
    let data = fs::read(bin).unwrap_or_else(|e| {
        panic!("failed to read {bin}: {}", e);
    });

    let mut address_space = unsafe { Task::with_pointer(data.as_ptr(), data.len()) };

    address_space.segments_protect();

    let mut linker = Linker::new();

    linker.link_raw(&mut address_space);

    jumper(address_space.memory, address_space.entry_point);
}
