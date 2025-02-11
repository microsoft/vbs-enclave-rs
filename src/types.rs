use core::{
    ffi::c_void,
    ops::{Deref, DerefMut},
};

use alloc::{boxed::Box, slice};

use crate::{error::EnclaveError, is_valid_vtl0, is_valid_vtl0_or_null};

pub trait VTL1Clonable<T: Copy> {
    fn clone_into_vtl1(&self) -> Result<T, EnclaveError>;
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct VTL0Ptr<T: Copy>(*const T);

impl<T: Copy> VTL0Ptr<T> {
    pub unsafe fn new(p: *const T) -> Result<Self, EnclaveError> {
        if is_valid_vtl0(p as *const _, size_of::<T>()) {
            Ok(Self(p))
        } else {
            Err(EnclaveError::invalid_arg())
        }
    }

    pub unsafe fn new_or_null(p: *const T) -> Result<Self, EnclaveError> {
        if is_valid_vtl0_or_null(p as *const _, size_of::<T>()) {
            Ok(Self(p))
        } else {
            Err(EnclaveError::invalid_arg())
        }
    }
}

// impl<T: Copy> From<*const T> for VTL0Ptr<T> {
//     fn from(value: *const T) -> Self {
//         Self(value)
//     }
// }

impl<T: Copy> VTL1Clonable<T> for VTL0Ptr<T> {
    fn clone_into_vtl1(&self) -> Result<T, EnclaveError> {
        unsafe { Ok(*self.0.clone()) }
    }
}

pub trait VTL1ClonableArray<T> {
    fn clone_into_vtl1(&self) -> Result<Box<[T]>, EnclaveError>;
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct VTL0Array<T> {
    buffer: *const T,
    count: usize,
}

impl<T: Copy> VTL1ClonableArray<T> for VTL0Array<T> {
    fn clone_into_vtl1(&self) -> Result<Box<[T]>, EnclaveError> {
        unsafe {
            if is_valid_vtl0(self.buffer as *const _, self.count * size_of::<T>()) {
                Ok(slice::from_raw_parts(self.buffer, self.count)
                    .to_vec()
                    .into_boxed_slice())
            } else {
                Err(EnclaveError::invalid_arg())
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
///     type Error = EnclaveError;
///     fn try_from(value: VTL0Ptr<VTL0MyParams>) -> Result<Self, Error> {
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
/// extern "C" fn my_enclave_function(param: VTL0Ptr<VTL0MyParams>) -> HRESULT {
///     let mut params = match VTL1MyParams::try_from(param) {
///         Ok(p) => p,
///         Err(e) => return HRESULT::from(e),
///     };
///
///     params.out.vtl1_owned.a = 1;
///     params.out.vtl1_owned.b = 2;
///
///     S_OK
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
pub struct VTL0MutPtr<T>(*mut T);

impl<T> VTL0MutPtr<T> {
    pub unsafe fn new(p: *mut T) -> Result<Self, EnclaveError> {
        if is_valid_vtl0(p as *const _, size_of::<T>()) {
            Ok(Self(p))
        } else {
            Err(EnclaveError::invalid_arg())
        }
    }
}

// impl<T: Copy + Default> From<*mut T> for VTL0MutPtr<T> {
//     fn from(value: *mut T) -> Self {
//         Self(value)
//     }
// }

impl<T> VTL0MutPtr<T> {
    // pub(crate) fn as_ptr(&self) -> *const Self {
    //     self as *const Self
    // }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut Self {
        self as *mut Self
    }

    pub fn as_ref(&self) -> &T {
        unsafe { &*self.0 }
    }

    pub fn as_mut_ref(&self) -> &mut T {
        unsafe { &mut *self.0 }
    }
}

impl<T: Copy + Default> TryFrom<VTL0MutPtr<T>> for VTL1MutPtr<T> {
    type Error = EnclaveError;

    fn try_from(value: VTL0MutPtr<T>) -> Result<Self, Self::Error> {
        if is_valid_vtl0(value.0 as *const _, size_of::<T>()) {
            unsafe {
                Ok(VTL1MutPtr {
                    vtl1_owned: Box::new(*value.0.clone()),
                    vtl0_ptr: value.0,
                })
            }
        } else {
            Err(EnclaveError::invalid_arg())
        }
    }
}

impl<T: Copy + Default> TryFrom<VTL1MutPtr<T>> for VTL0MutPtr<T> {
    type Error = EnclaveError;

    fn try_from(value: VTL1MutPtr<T>) -> Result<Self, Self::Error> {
        if is_valid_vtl0(value.vtl0_ptr as *const _, size_of::<T>()) {
            Ok(VTL0MutPtr(value.vtl0_ptr))
        } else {
            Err(EnclaveError::invalid_arg())
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

#[allow(non_camel_case_types)]
pub type LPENCLAVE_ROUTINE = isize;

pub struct VTL0Callback<T, U>(fn(T) -> U);

impl<T: Copy + Default, U: Copy + Default> VTL0Callback<T, U> {
    pub unsafe fn new(fp: LPENCLAVE_ROUTINE) -> Result<Self, EnclaveError> {
        // Size doesn't really matter here because we don't know the bounds
        // of the function itself. As long as fp is vtl0, it's fine.
        if is_valid_vtl0(fp as *const c_void, 1) {
            Ok(Self(core::mem::transmute::<LPENCLAVE_ROUTINE, fn(T) -> U>(
                fp,
            )))
        } else {
            Err(EnclaveError::invalid_arg())
        }
    }
}

impl<T, U> VTL0Callback<T, U>
where
    T: Copy + Default,
    U: Copy + Default,
{
    pub fn try_from(value: LPENCLAVE_ROUTINE) -> Result<Self, EnclaveError> {
        unsafe {
            // Doing this instead of the reverse because it gets rid of the warning that
            // VTL0Callback<T, U>.0 is never read
            let s = Self(core::mem::transmute::<LPENCLAVE_ROUTINE, fn(T) -> U>(value));

            if !is_valid_vtl0(s.0 as *const _, core::mem::size_of::<isize>()) {
                return Err(EnclaveError::invalid_arg());
            }

            Ok(s)
        }
    }
}