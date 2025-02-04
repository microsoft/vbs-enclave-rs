#![no_std]

mod allocator;
pub mod types;
pub mod winenclave;

extern crate alloc;

use core::sync::atomic::{AtomicUsize, Ordering};

use winenclave::get_enclave_information;

use core::panic::PanicInfo;
#[panic_handler]
// this will get red squiggles in vscode unless you set
// "rust-analyzer.check.allTargets": false
fn panic(_panic: &PanicInfo<'_>) -> ! {
    loop {}
}

pub static ENCLAVE_BASE: AtomicUsize = AtomicUsize::new(0);
pub static ENCLAVE_END: AtomicUsize = AtomicUsize::new(0);

pub fn is_valid_vtl0(start: usize, size: usize) -> bool {
    let base = ENCLAVE_BASE.load(Ordering::Relaxed);

    let end = ENCLAVE_END.load(Ordering::Relaxed);

    return start != 0 && (start + size < base || start > end);
}

#[no_mangle]
pub extern "system" fn dllmain() -> bool {
    // Calculate this enclave's start and end addresses, so VTL0
    // pointers can be validated during enclave functions.
    let info = match get_enclave_information() {
        Ok(i) => i,
        _ => return false,
    };

    ENCLAVE_BASE.store(info.base_address(), Ordering::Relaxed);
    ENCLAVE_END.store(info.base_address() + info.size(), Ordering::Relaxed);

    true
}
