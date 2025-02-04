#![no_std]
use core::ffi::c_void;
use core::ptr;

mod allocator;
pub mod types;
pub mod winenclave;

extern crate alloc;

use core::sync::atomic::{AtomicPtr, Ordering};

use winenclave::get_enclave_information;

use core::panic::PanicInfo;
#[panic_handler]
// this will get red squiggles in vscode unless you set
// "rust-analyzer.check.allTargets": false
fn panic(_panic: &PanicInfo<'_>) -> ! {
    loop {}
}

static ENCLAVE_BASE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static ENCLAVE_END: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

pub fn is_valid_vtl0(base: *const c_void, size: usize) -> bool {
    let enclave_base = ENCLAVE_BASE.load(Ordering::Relaxed) as *const _;
    let enclave_end = ENCLAVE_END.load(Ordering::Relaxed) as *const _;

    let end = base.wrapping_byte_add(size);

    !base.is_null() && ((end < enclave_base) || (enclave_end <= base))
}

#[no_mangle]
pub extern "system" fn dllmain() -> bool {
    // Calculate this enclave's start and end addresses, so VTL0
    // pointers can be validated during enclave functions.
    let info = match get_enclave_information() {
        Ok(i) => i,
        _ => return false,
    };

    let end = info.BaseAddress.wrapping_byte_add(info.Size);

    ENCLAVE_BASE.store(info.BaseAddress, Ordering::Relaxed);
    ENCLAVE_END.store(end, Ordering::Relaxed);

    true
}
