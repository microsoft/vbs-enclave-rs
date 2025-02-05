pub use windows_sys::core::HRESULT;
use windows_sys::Win32::Foundation::E_INVALIDARG;
pub use windows_sys::Win32::Foundation::S_OK;

pub(crate) fn check_hr(hresult: HRESULT) -> Result<(), EnclaveError> {
    if hresult == S_OK {
        Ok(())
    } else {
        Err(EnclaveError { hresult })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("enclave error: {hresult:x}")]
pub struct EnclaveError {
    pub hresult: HRESULT,
}

impl EnclaveError {
    pub fn invalid_arg() -> Self {
        Self {
            hresult: E_INVALIDARG,
        }
    }
}

impl From<EnclaveError> for HRESULT {
    fn from(err: EnclaveError) -> Self {
        err.hresult
    }
}
