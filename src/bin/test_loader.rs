use loader::{ErrCode, execvm};
use std::fs;

fn main() {
    let bin = "./binaries/hello_world_static/hello_world";
    let data = fs::read(bin).unwrap_or_else(|e| {
        panic!("failed to read {bin}: {}", e);
    });

    println!("[exec]: loaded mach-o {bin}: {}b", data.len());

    let result = execvm(data.as_ptr(), data.len(), bin.as_ptr(), bin.len());

    match result {
        ErrCode::OK => println!("[+] execvm succeeded"),
        err => {
            panic!("[-] execvm failed: {:?}", err);
        }
    }
}
