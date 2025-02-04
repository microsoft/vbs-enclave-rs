use core::alloc::{GlobalAlloc, Layout};

extern "C" {
    fn malloc(s: usize) -> *mut u8;
    fn free(p: *const u8);
}

#[repr(C)]
pub struct EnclaveAllocator {}

unsafe impl GlobalAlloc for EnclaveAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let _align = layout.align();

        malloc(size)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        free(ptr);
    }
}

#[global_allocator]
static ALLOCATOR: EnclaveAllocator = EnclaveAllocator {};
