use loader::{ErrCode, execvm};
use std::fs;

const BIN_NAME: &'static str = "/bin/ls";

fn main() {
    let data = fs::read(BIN_NAME).unwrap_or_else(|e| {
        panic!("failed to read {BIN_NAME}: {}", e);
    });

    println!("[exec]: loaded mach-o {BIN_NAME}: {}b", data.len());

    let result = execvm(data.as_ptr(), data.len());

    match result {
        ErrCode::OK => println!("[+] execvm succeeded"),
        err => {
            panic!("[-] execvm failed: {:?}", err);
        }
    }
}
