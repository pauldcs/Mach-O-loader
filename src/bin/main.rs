use std::env;
use std::fs;

use loader::{Task, jumper::jumper, linker::Linker};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        panic!("invalid number of arguments");
    }

    let bin = &args[1];

    let data = fs::read(bin).unwrap_or_else(|e| {
        panic!("failed to read {bin}: {}", e);
    });

    let mut task = unsafe { Task::with_pointer(data.as_ptr(), data.len()) };

    task.segments_protect();

    let mut linker = Linker::new();

    linker.link_raw(&mut task);

    jumper(task.memory, task.entry_point);
}
