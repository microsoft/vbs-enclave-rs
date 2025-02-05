extern crate alloc;
use alloc::boxed::Box;
use vbs_enclave::NativeHResult;
use vbs_enclave::types::{
    VTL0Array, VTL0MutPtr, VTL0Ptr, VTL1Clonable, VTL1ClonableArray, VTL1MutPtr,
};

/// VTL0 C++ Structure:
/// ```
/// struct VTL0Array<T> {
///     _In_ T* arr;
///     _In_ size_t count;
/// }
/// struct MyEnclaveParams {
///     _In_ uint32_t a;
///     _In_ uint32_t b;
///     _In_ uint32_t* c;
///     _In_ VTL0Array<uint32_t> d;
///     _Out_ uint32_t* e;
/// }
/// ```

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MyEnclaveParams {
    pub a: u32,
    pub b: u32,
    pub c: VTL0Ptr<u32>,
    pub d: VTL0Array<u32>,
    pub e: VTL0MutPtr<u32>,
}

pub struct VTL1MyEnclaveParams {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: Box<[u32]>,
    pub e: VTL1MutPtr<u32>,
}

impl TryFrom<VTL0Ptr<MyEnclaveParams>> for VTL1MyEnclaveParams {
    type Error = NativeHResult;
    fn try_from(value: VTL0Ptr<MyEnclaveParams>) -> Result<Self, Self::Error> {
        let vtl1_clone = value.clone_into_vtl1()?;
        let c: u32 = vtl1_clone.c.clone_into_vtl1()?;
        let d: Box<[u32]> = vtl1_clone.d.clone_into_vtl1()?;
        let e: VTL1MutPtr<u32> = vtl1_clone.e.try_into()?;
        Ok(Self {
            a: vtl1_clone.a,
            b: vtl1_clone.b,
            c,
            d,
            e,
        })
    }
}
