use core::ops::{Deref, DerefMut};

use alloc::{boxed::Box, slice};

use crate::{
    is_valid_vtl0,
    HResultError,
    NativeHResult
};

pub trait VTL1Clonable<T: Copy> {
    fn clone_into_vtl1(&self) -> Result<T, NativeHResult>;
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct VTL0Ptr<T: Copy>(*const T);

impl<T: Copy> VTL1Clonable<T> for VTL0Ptr<T> {
    fn clone_into_vtl1(&self) -> Result<T, NativeHResult> {
        unsafe {
            if is_valid_vtl0(self.0 as *const _, size_of::<T>()) {
                Ok(*self.0.clone())
            } else {
                Err(HResultError::InvalidArgument as NativeHResult)
            }
        }
    }
}

pub trait VTL1ClonableArray<T> {
    fn clone_into_vtl1(&self) -> Result<Box<[T]>, NativeHResult>;
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct VTL0Array<T> {
    buffer: *const T,
    count: usize,
}

impl<T: Copy> VTL1ClonableArray<T> for VTL0Array<T> {
    fn clone_into_vtl1(&self) -> Result<Box<[T]>, NativeHResult> {
        unsafe {
            if is_valid_vtl0(self.buffer as *const _, self.count * size_of::<T>()) {
                Ok(slice::from_raw_parts(self.buffer, self.count)
                    .to_vec()
                    .into_boxed_slice())
            } else {
                Err(HResultError::InvalidArgument as NativeHResult)
            }
        }
    }
}

/// Mutable VTL0 Pointer
/// If your function needs to flush some sort of structure back to VTL0 when the call
/// completes, you can express that as a VTL0MutPtr in your VTL0 struct, and as a
/// VTL1MutPtr in your VTL1 struct.
///
/// Example:
/// ```
/// #[repr(C)]
/// #[derive(Copy, Clone, Default)]
/// struct MyOutputType {
///     a: u32,
///     b: u32
/// }
///
/// #[repr(C)]
/// #[derive(Copy, Clone)]
/// struct VTL0MyParams {
///     in1: u32,
///     in2: u32,
///     out: VTL0MutPtr<MyOutputType>
/// }
///
/// struct VTL1MyParams {
///     in1: u32,
///     in2: u32,
///     out: VTL1MutPtr<MyOutputType>
/// }
///
/// impl TryFrom<VTL0Ptr<VTL0MyParams>> for VTL1MyParams {
///     type Error = NativeHResult;
///     fn try_from(value: VTL0Ptr<VTL0MyParams>) -> Result<Self, Self::Error> {
///         let vtl1_clone = value.clone_into_vtl1()?;
///         let out = vtl1_clone.out.try_into()?;
///         Ok(Self {
///             in1: vtl1_clone.in1,
///             in2: vtl1_clone.in2,
///             out,
///         })
///     }
/// }
///
/// #[no_mangle]
/// extern "C" fn my_enclave_function(param: VTL0Ptr<VTL0MyParams>) -> NativeHResult {
///     let mut params = match VTL1MyParams::try_from(param) {
///         Ok(p) => p,
///         Err(e) => return e,
///     };
///
///     params.out.vtl1_owned.a = 1;
///     params.out.vtl1_owned.b = 2;
///
///     HResultSuccess::Ok as NativeHResult
///
///     // params.out.vtl1_owned will be written to param.out when params goes
///     // out of scope here
/// }
/// ```
pub struct VTL1MutPtr<T: Copy + Default> {
    vtl1_owned: Box<T>,
    vtl0_ptr: *mut T,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct VTL0MutPtr<T: Copy + Default> {
    p: *mut T,
}

impl<T: Copy + Default> TryFrom<VTL0MutPtr<T>> for VTL1MutPtr<T> {
    type Error = NativeHResult;
    fn try_from(value: VTL0MutPtr<T>) -> Result<Self, Self::Error> {
        if is_valid_vtl0(value.p as *const _, size_of::<T>()) {
            unsafe {
                Ok(VTL1MutPtr {
                    vtl1_owned: Box::new(*value.p.clone()),
                    vtl0_ptr: value.p,
                })
            }
        } else {
            Err(HResultError::InvalidArgument as NativeHResult)
        }
    }
}

impl<T> Drop for VTL1MutPtr<T>
where
    T: Copy,
    T: Default,
{
    fn drop(&mut self) {
        unsafe {
            *self.vtl0_ptr = *self.vtl1_owned;
        }
    }
}

impl<T: ?Sized + Copy + Default> Deref for VTL1MutPtr<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.vtl1_owned
    }
}

impl<T: ?Sized + Copy + Default> DerefMut for VTL1MutPtr<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.vtl1_owned
    }
}
