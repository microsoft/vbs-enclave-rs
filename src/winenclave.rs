use core::mem::{offset_of, MaybeUninit};

use alloc::vec::Vec;

use windows_sys::Win32::System::Environment::{
    EnclaveGetAttestationReport,
    EnclaveGetEnclaveInformation,
    EnclaveSealData,
    EnclaveUnsealData,
    ENCLAVE_IDENTITY,
    ENCLAVE_INFORMATION
};

use crate::{HResultError, NativeHResult};

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
#[derive(Clone, Copy)]
pub enum SealingIdentityPolicy {
    Invalid = 0,
    ExactCode = 1,
    PrimaryCode = 2,
    SameImage = 3,
    SameFamily = 4,
    SameAuthor = 5,
}

#[repr(u32)]
#[derive(Clone, Copy)]
pub enum SealingRuntimePolicy {
    None = 0,
    AllowFullDebug = 1,
    AllowDynamicDebug = 2,
}

pub fn get_attestation_report(
    enclave_data: Option<&[u8; ENCLAVE_REPORT_DATA_LENGTH]>,
) -> Result<Vec<u8>, NativeHResult> {
    let mut output_size: u32 = 0;
    let mut report: Vec<u8> = Vec::new();
    let data = if let Some(v) = enclave_data {
        v as *const u8
    } else {
        core::ptr::null()
    };

    unsafe {
        match EnclaveGetAttestationReport(
            data,
            core::ptr::null_mut(),
            0,
            &mut output_size,
        ) {
            0 => {}
            e => return Err(e),
        }
    }

    report.resize(output_size as usize, 0);

    unsafe {
        match EnclaveGetAttestationReport(
            data,
            report.as_mut_ptr() as *mut _,
            report.len() as u32,
            &mut output_size,
        ) {
            0 => {}
            e => return Err(e),
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
            e => Err(e),
        }
    }
}

pub fn seal_data(
    data: &[u8],
    identity_policy: SealingIdentityPolicy,
    runtime_policy: SealingRuntimePolicy
) -> Result<Vec<u8>, NativeHResult> {
    let Ok(data_to_encrypt_size) = u32::try_from(data.len()) else {
        return Err(HResultError::InvalidArgument as NativeHResult);
    };

    let mut output_size: u32 = 0;

    unsafe {
        match EnclaveSealData(
            data.as_ptr() as _,
            data_to_encrypt_size,
            identity_policy as i32,
            runtime_policy as u32,
            core::ptr::null_mut(),
            0,
            &mut output_size
        ) {
            0 => {}
            e => return Err(e),
        }
    }

    let mut sealed_data = Vec::new();
    sealed_data.resize(output_size as usize, 0);

    unsafe {
        match EnclaveSealData(
            data.as_ptr() as _,
            data_to_encrypt_size,
            identity_policy as i32,
            runtime_policy as u32,
            sealed_data.as_mut_ptr() as _,
            sealed_data.len() as u32,
            &mut output_size
        ) {
            0 => {}
            e => return Err(e),
        }
    }

    Ok(sealed_data)
}

pub fn unseal_data(data: &[u8], sealing_identity: Option<&mut ENCLAVE_IDENTITY>, unsealing_flags: Option<u32>) -> Result<Vec<u8>, NativeHResult> {
    let Ok(data_to_decrypt_len) = u32::try_from(data.len()) else {
        return Err(HResultError::InvalidArgument as NativeHResult);
    };

    let sealingidentity = if let Some(v) = sealing_identity {
        v as *mut _
    } else {
        core::ptr::null_mut()
    };

    let unsealingflags = if let Some(v) = unsealing_flags {
        v as *mut _
    } else {
        core::ptr::null_mut()
    };

    let mut decrypted_data_size = 0u32;

    unsafe {
        match EnclaveUnsealData(
            data.as_ptr() as _,
            data_to_decrypt_len,
            core::ptr::null_mut(),
            0,
            &mut decrypted_data_size as _,
            sealingidentity,
            unsealingflags
        ) {
            0 => {}
            e => return Err(e),
        }
    }

    let mut decrypted_data: Vec<u8> = Vec::new();
    decrypted_data.resize(decrypted_data_size as usize, 0);

    unsafe {
        match EnclaveUnsealData(
            data.as_ptr() as _,
            data_to_decrypt_len,
            decrypted_data.as_mut_ptr() as _,
            decrypted_data.len() as u32,
            &mut decrypted_data_size as _,
            sealingidentity,
            unsealingflags
        ) {
            0 => {}
            e => return Err(e),
        }
    }

    Ok(decrypted_data)
}