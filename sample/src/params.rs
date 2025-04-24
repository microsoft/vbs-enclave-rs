use vbs_enclave::enclaveapi::{call_enclave, EnclaveRoutineInvocation};
use vbs_enclave::error::EnclaveError;
use vbs_enclave::is_valid_vtl0;
use vbs_enclave::types::LPENCLAVE_ROUTINE;

#[repr(C)]
#[derive(Clone, Copy, zerocopy::TryFromBytes, zerocopy::KnownLayout, zerocopy::Immutable)]
pub struct AllocationCallback(LPENCLAVE_ROUTINE);

impl AllocationCallback {
    pub fn call(&self, size: usize) -> Result<*mut u8, EnclaveError> {
        if !is_valid_vtl0(self.0 as *const core::ffi::c_void, 1) {
            Err(EnclaveError::invalid_arg())
        } else {
            let invocation = unsafe { EnclaveRoutineInvocation::new(self.0, size as *const _) };
            match call_enclave(invocation, true) {
                Ok(ptr) => Ok(ptr as *mut u8),
                Err(e) => Err(e),
            }
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, zerocopy::TryFromBytes, zerocopy::KnownLayout, zerocopy::Immutable)]
pub struct NewKeypairParams {
    // Only 256 is supported, because it needs to fit into the report
    pub key_size: u32,
    public_key_blob: usize,
}

impl NewKeypairParams {
    pub fn public_key_blob(&self) -> *const u8 {
        self.public_key_blob as *const u8
    }
}

#[repr(C)]
#[derive(Clone, Copy, zerocopy::TryFromBytes, zerocopy::KnownLayout, zerocopy::Immutable)]
pub struct GenerateReportParams {
    pub allocate_callback: AllocationCallback,
    pub report_size: usize,
    report: usize,
}

impl GenerateReportParams {
    pub fn set_report(&mut self, report: *const u8) {
        self.report = report as usize;
    }
}

#[repr(C)]
#[derive(Clone, Copy, zerocopy::TryFromBytes, zerocopy::KnownLayout, zerocopy::Immutable)]
pub struct DecryptDataParams {
    pub allocate_callback: AllocationCallback,
    pub encrypted_size: usize,
    encrypted_data: usize,
    pub iv_size: usize,
    iv: usize,
    pub tag_size: usize,
    tag: usize,
    pub decrypted_size: usize,
    decrypted_data: usize,  /* out parameter */
}

impl DecryptDataParams {
    pub fn encrypted_data(&self) -> *const u8 {
        self.encrypted_data as *const u8
    }

    pub fn iv(&self) -> *const u8 {
        self.iv as *const u8
    }

    pub fn tag(&self) -> *const u8 {
        self.tag as *const u8
    }

    pub fn set_decrypted_data(&mut self, decrypted_data: *const u8) {
        self.decrypted_data = decrypted_data as usize;
    }
}
