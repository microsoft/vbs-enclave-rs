pub use windows_sys::core::HRESULT;
pub use windows_sys::Win32::Foundation::S_OK;
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, E_INVALIDARG};

pub(crate) fn check_hr(hresult: HRESULT) -> Result<(), EnclaveError> {
    if hresult == S_OK {
        Ok(())
    } else {
        Err(EnclaveError { hresult })
    }
}

pub fn hresult_from_win32(e: u32) -> HRESULT {
    let facility_win32 = 0x0007u32;

    if e > 0 {
        ((e & 0x0000_ffff) as u32 | (facility_win32 << 16) | 0x8000_0000u32) as HRESULT
    } else {
        e as HRESULT
    }
}

pub fn hresult_from_nt(e: i32) -> HRESULT {
    let facility_nt_bit = 0x1000_0000;

    (e | facility_nt_bit) as HRESULT
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

    // HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)
    pub fn insufficient_buffer() -> Self {
        Self {
            hresult: hresult_from_win32(ERROR_INSUFFICIENT_BUFFER),
        }
    }
}

impl From<EnclaveError> for HRESULT {
    fn from(err: EnclaveError) -> Self {
        err.hresult
    }
}
