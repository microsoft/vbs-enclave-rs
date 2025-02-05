use windows_sys::Win32::Foundation::E_INVALIDARG;
pub use windows_sys::core::HRESULT;

#[allow(private_bounds)]
pub(crate) trait CheckHResult: Sealed {
    fn check(self) -> Result<(), Error>;
}

// Impl for `HRESULT` from `windows-sys`, only.
impl CheckHResult for HRESULT {
    fn check(self) -> Result<(), Error> {
        if self == 0 {
            Ok(())
        } else {
            Err(Error { hresult: self })
        }
    }
}

trait Sealed {}
impl Sealed for HRESULT {}

#[derive(Debug, thiserror::Error)]
#[error("enclave error: {hresult:x}")]
pub struct Error {
    pub hresult: HRESULT,
}

impl Error {
    pub fn invalid_arg() -> Self {
        Self {
            hresult: E_INVALIDARG,
        }
    }
}

impl From<Error> for HRESULT {
    fn from(err: Error) -> Self {
        err.hresult
    }
}
