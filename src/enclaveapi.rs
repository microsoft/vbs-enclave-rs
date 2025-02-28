use crate::error::EnclaveError;
use crate::types::LPENCLAVE_ROUTINE;
use core::ffi::c_void;
use windows_sys::Win32::Foundation::TRUE;
use windows_sys::Win32::System::Environment::CallEnclave;

// The enclave routine and parameter cannot be known to
// be valid memory across the trust boundary, so we use
// a struct to hold these values and mark the creation
// of this struct as unsafe as a point in which the unsafe
// assumption occurs.
pub struct EnclaveRoutineInvocation {
    routine: LPENCLAVE_ROUTINE,
    param: *const c_void,
}

impl EnclaveRoutineInvocation {
    /// SAFETY: `routine` and `param` could potentially be
    /// invalid pointers; `routine` must be a valid function pointer,
    /// and `param` must be a valid parameter for the function pointer,
    /// either an integer value that is expected, or a valid allocation.
    pub unsafe fn new(routine: LPENCLAVE_ROUTINE, param: *const c_void) -> Self {
        Self { routine, param }
    }
}

pub fn call_enclave(
    invocation: EnclaveRoutineInvocation,
    wait_for_thread: bool,
) -> Result<*mut c_void, EnclaveError> {
    // Things to add:
    // 1. checking that the routine pointer is in vtl0 -- can this be done with a template?
    // 2. validation on parameter (not a vtl1 pointer, mostly as info leak)
    // 3. (optional) validation and copying of return value
    // 4. (optional) typing of parameter passed using vtl1_clonable traits etc
    // 5. return the return value parameter in a Result instead of just Ok

    let mut return_value = core::ptr::null_mut();

    let success = unsafe {
        CallEnclave(
            invocation.routine,
            invocation.param,
            wait_for_thread as _,
            &mut return_value,
        )
    };

    if success == TRUE {
        Ok(return_value)
    } else {
        // TODO: Use GetLastError() and convert to HRESULT?
        Err(EnclaveError::invalid_arg())
    }
}
