use crate::error::EnclaveError;
use crate::types::LPENCLAVE_ROUTINE;
use core::ffi::c_void;
use windows_sys::Win32::Foundation::TRUE;
use windows_sys::Win32::System::Environment::CallEnclave;

pub fn call_enclave(
    routine: LPENCLAVE_ROUTINE,
    param: *mut c_void,
    wait_for_thread: bool,
    return_value: *mut *mut c_void,
) -> Result<(), EnclaveError> {
    // Things to add:
    // 1. checking that the routine pointer is in vtl0 -- can this be done with a template?
    // 2. validation on parameter (not a vtl1 pointer, mostly as info leak)
    // 3. (optional) validation and copying of return value
    // 4. (optional) typing of parameter passed using vtl1_clonable traits etc
    // 5. return the return value parameter in a Result instead of just Ok

    let success = unsafe { CallEnclave(routine, param, wait_for_thread as _, return_value) };

    if success == TRUE {
        Ok(())
    } else {
        // TODO: Use GetLastError() and convert to HRESULT?
        Err(EnclaveError::invalid_arg())
    }
}
