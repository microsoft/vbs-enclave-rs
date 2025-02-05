pub use windows_sys::core::HRESULT;
use windows_sys::Win32::Foundation::E_INVALIDARG;
pub use windows_sys::Win32::Foundation::S_OK;

#[allow(private_bounds)]
pub(crate) trait CheckHResult: Sealed {
    fn check(self) -> Result<(), EnclaveError>;
}

// Impl for `HRESULT` from `windows-sys`, only.
impl CheckHResult for HRESULT {
    fn check(self) -> Result<(), EnclaveError> {
        if self == 0 {
            Ok(())
        } else {
            Err(EnclaveError { hresult: self })
        }
    }
}

trait Sealed {}
impl Sealed for HRESULT {}

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
