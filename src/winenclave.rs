use core::mem::{offset_of, MaybeUninit};

use alloc::vec::Vec;

use windows_sys::Win32::System::Environment::{
    ENCLAVE_INFORMATION,
    EnclaveGetAttestationReport,
    EnclaveGetEnclaveInformation,
};

pub const ENCLAVE_LONG_ID_LENGTH: usize = 32;
pub const ENCLAVE_SHORT_ID_LENGTH: usize = 16;

pub const IMAGE_ENCLAVE_LONG_ID_LENGTH: usize = ENCLAVE_LONG_ID_LENGTH;
pub const IMAGE_ENCLAVE_SHORT_ID_LENGTH: usize = ENCLAVE_SHORT_ID_LENGTH;
pub const IMAGE_ENCLAVE_POLICY_DEBUGGABLE: u32 = 0x0000_0001;
pub const IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE: u32 = 0x0000_0001;

pub const ENCLAVE_FLAG_FULL_DEBUG_ENABLED: u32 = 0x0000_0001;

pub const ENCLAVE_FLAG_DYNAMIC_DEBUG_ENABLED: u32 = 0x0000_0002;

pub const ENCLAVE_FLAG_DYNAMIC_DEBUG_ACTIVE: u32 = 0x0000_0004;

pub const ENCLAVE_REPORT_DATA_LENGTH: usize = 64;

// struct _IMAGE_ENCLAVE_CONFIG64 {
//     DWORD Size;
//     DWORD MinimumRequiredConfigSize;
//     DWORD PolicyFlags;
//     DWORD NumberOfImports;
//     DWORD ImportList;
//     DWORD ImportEntrySize;
//     BYTE  FamilyID[IMAGE_ENCLAVE_SHORT_ID_LENGTH];
//     BYTE  ImageID[IMAGE_ENCLAVE_SHORT_ID_LENGTH];
//     DWORD ImageVersion;
//     DWORD SecurityVersion;
//     ULONGLONG EnclaveSize;
//     DWORD NumberOfThreads;
//     DWORD EnclaveFlags;
// }

#[repr(C)]
// #[allow(non_camel_case_types)]
pub struct ImageEnclaveConfig {
    pub size: u32,
    pub minimum_required_config_size: u32,
    pub policy_flags: u32,
    pub number_of_imports: u32,
    pub import_list: u32,
    pub import_entry_size: u32,
    pub family_id: [u8; IMAGE_ENCLAVE_SHORT_ID_LENGTH],
    pub image_id: [u8; IMAGE_ENCLAVE_SHORT_ID_LENGTH],
    pub image_version: u32,
    pub security_version: u32,
    pub enclave_size: usize,
    pub number_of_threads: u32,
    pub enclave_flags: u32,
}

pub const IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE: u32 =
    offset_of!(ImageEnclaveConfig, enclave_flags) as u32;

#[repr(u32)]
pub enum HResultSuccess {
    Ok = 0,
    False = 1,
}

#[repr(u32)]
pub enum HResultError {
    InvalidArgument = 0x80070057,
    InvalidState = 0x8007139f,
    Unexpected = 0x8000ffff,
}

impl TryFrom<u32> for HResultError {
    type Error = u32;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            x if x == HResultError::InvalidArgument as u32 => Ok(HResultError::InvalidArgument),
            x if x == HResultError::InvalidState as u32 => Ok(HResultError::InvalidState),
            x if x == HResultError::Unexpected as u32 => Ok(HResultError::Unexpected),
            x => Err(x),
        }
    }
}

pub type NativeHResult = u32;
pub type HResult = Result<HResultSuccess, NativeHResult>;

#[repr(u32)]
pub enum SealingIdentityPolicy {
    Invalid = 0,
    ExactCode = 1,
    PrimaryCode = 2,
    SameImage = 3,
    SameFamily = 4,
    SameAuthor = 5,
}

#[repr(u32)]
pub enum SealingRuntimePolicy {
    AllowFullDebug = 1,
    AllowDynamicDebug = 2,
}

pub fn get_attestation_report(
    enclave_data: &[u8; ENCLAVE_REPORT_DATA_LENGTH],
) -> Result<Vec<u8>, NativeHResult> {
    let mut output_size: u32 = 0;
    let mut report: Vec<u8> = Vec::new();
    unsafe {
        match EnclaveGetAttestationReport(
            enclave_data as *const u8,
            core::ptr::null_mut(),
            0,
            &mut output_size,
        ) {
            0 => {}
            e => return Err(e as u32),
        }
    }

    report.resize(output_size as usize, 0);

    unsafe {
        match EnclaveGetAttestationReport(
            enclave_data as *const u8,
            report.as_mut_ptr() as *mut _,
            report.len() as u32,
            &mut output_size,
        ) {
            0 => {}
            e => return Err(e as u32),
        }
    }

    Ok(report)
}

pub fn get_enclave_information() -> Result<ENCLAVE_INFORMATION, NativeHResult> {
    let mut info = MaybeUninit::zeroed();
    unsafe {
        match EnclaveGetEnclaveInformation(
            size_of::<ENCLAVE_INFORMATION>() as u32,
            info.as_mut_ptr(),
        ) {
            0 => Ok(info.assume_init()),
            e => Err(e as u32),
        }
    }
}
