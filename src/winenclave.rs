use core::mem::{offset_of, MaybeUninit};

use alloc::vec::Vec;

use windows_sys::{
    core::HRESULT,
    Win32::{
        Foundation::BOOL,
        System::Environment::{
            EnclaveGetAttestationReport, EnclaveGetEnclaveInformation, EnclaveSealData,
            EnclaveUnsealData, ENCLAVE_IDENTITY, ENCLAVE_INFORMATION, ENCLAVE_REPORT_DATA_LENGTH,
        },
    },
};

use crate::error::{check_hr, EnclaveError};

pub const ENCLAVE_LONG_ID_LENGTH: usize = 32;
pub const ENCLAVE_SHORT_ID_LENGTH: usize = 16;

pub const IMAGE_ENCLAVE_LONG_ID_LENGTH: usize = ENCLAVE_LONG_ID_LENGTH;
pub const IMAGE_ENCLAVE_SHORT_ID_LENGTH: usize = ENCLAVE_SHORT_ID_LENGTH;
pub const IMAGE_ENCLAVE_POLICY_DEBUGGABLE: u32 = 0x0000_0001;
pub const IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE: u32 = 0x0000_0001;

pub const ENCLAVE_FLAG_FULL_DEBUG_ENABLED: u32 = 0x0000_0001;

pub const ENCLAVE_FLAG_DYNAMIC_DEBUG_ENABLED: u32 = 0x0000_0002;

pub const ENCLAVE_FLAG_DYNAMIC_DEBUG_ACTIVE: u32 = 0x0000_0004;

// This isn't in windows-rs yet, so define it here for now
pub const IMAGE_ENCLAVE_POLICY_STRICT_MEMORY: u32 = 0x0000_0002;

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
    enclave_data: Option<&[u8; ENCLAVE_REPORT_DATA_LENGTH as usize]>,
) -> Result<Vec<u8>, EnclaveError> {
    let mut output_size: u32 = 0;
    let mut report: Vec<u8> = Vec::new();
    let data = if let Some(v) = enclave_data {
        v as *const u8
    } else {
        core::ptr::null()
    };

    let hr =
        unsafe { EnclaveGetAttestationReport(data, core::ptr::null_mut(), 0, &mut output_size) };
    check_hr(hr)?;

    report.resize(output_size as usize, 0);

    let hr = unsafe {
        EnclaveGetAttestationReport(
            data,
            report.as_mut_ptr() as *mut _,
            report.len() as u32,
            &mut output_size,
        )
    };
    check_hr(hr)?;

    Ok(report)
}

pub fn get_enclave_information() -> Result<ENCLAVE_INFORMATION, EnclaveError> {
    let mut info = MaybeUninit::zeroed();
    let hr = unsafe {
        EnclaveGetEnclaveInformation(size_of::<ENCLAVE_INFORMATION>() as u32, info.as_mut_ptr())
    };
    check_hr(hr)?;

    let info = unsafe {
        // SAFETY: only reachable if above HResult check passes.
        info.assume_init()
    };

    Ok(info)
}

pub fn seal_data(
    data: &[u8],
    identity_policy: SealingIdentityPolicy,
    runtime_policy: SealingRuntimePolicy,
) -> Result<Vec<u8>, EnclaveError> {
    let Ok(data_to_encrypt_size) = u32::try_from(data.len()) else {
        return Err(EnclaveError::invalid_arg());
    };

    let mut output_size: u32 = 0;

    let hr = unsafe {
        EnclaveSealData(
            data.as_ptr() as _,
            data_to_encrypt_size,
            identity_policy as i32,
            runtime_policy as u32,
            core::ptr::null_mut(),
            0,
            &mut output_size,
        )
    };
    check_hr(hr)?;

    let mut sealed_data = Vec::new();
    sealed_data.resize(output_size as usize, 0);

    let hr = unsafe {
        EnclaveSealData(
            data.as_ptr() as _,
            data_to_encrypt_size,
            identity_policy as i32,
            runtime_policy as u32,
            sealed_data.as_mut_ptr() as _,
            sealed_data.len() as u32,
            &mut output_size,
        )
    };
    check_hr(hr)?;

    Ok(sealed_data)
}

pub fn unseal_data(
    data: &[u8],
    sealing_identity: Option<&mut ENCLAVE_IDENTITY>,
    unsealing_flags: Option<u32>,
) -> Result<Vec<u8>, EnclaveError> {
    let Ok(data_to_decrypt_len) = u32::try_from(data.len()) else {
        return Err(EnclaveError::invalid_arg());
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

    let hr = unsafe {
        EnclaveUnsealData(
            data.as_ptr() as _,
            data_to_decrypt_len,
            core::ptr::null_mut(),
            0,
            &mut decrypted_data_size as _,
            sealingidentity,
            unsealingflags,
        )
    };
    check_hr(hr)?;

    let mut decrypted_data: Vec<u8> = Vec::new();
    decrypted_data.resize(decrypted_data_size as usize, 0);

    let hr = unsafe {
        EnclaveUnsealData(
            data.as_ptr() as _,
            data_to_decrypt_len,
            decrypted_data.as_mut_ptr() as _,
            decrypted_data.len() as u32,
            &mut decrypted_data_size as _,
            sealingidentity,
            unsealingflags,
        )
    };
    check_hr(hr)?;

    Ok(decrypted_data)
}

// These functions aren't in windows-rs yet, so we define them here.
#[link(name = "vertdll")]
extern "C" {
    fn EnclaveCopyIntoEnclave(
        enclave_address: *mut core::ffi::c_void,
        unsecure_address: *const core::ffi::c_void,
        number_of_bytes: usize,
    ) -> HRESULT;

    fn EnclaveCopyOutOfEnclave(
        unsecure_address: *mut core::ffi::c_void,
        enclave_address: *const core::ffi::c_void,
        number_of_bytes: usize,
    ) -> HRESULT;

    fn EnclaveRestrictContainingProcessAccess(
        restrict_access: BOOL,
        previously_restricted: *mut BOOL,
    ) -> HRESULT;
}

pub fn restrict_containing_process_access(restrict_access: bool) -> Result<bool, EnclaveError> {
    let mut previously_restricted: BOOL = 0;
    let hr = unsafe {
        EnclaveRestrictContainingProcessAccess(restrict_access as _, &mut previously_restricted)
    };
    check_hr(hr)?;

    Ok(previously_restricted != 0)
}

pub fn copy_slice_into_enclave(
    vtl1_dest: &mut [u8],
    vtl0_src: *const u8,
) -> Result<(), EnclaveError> {
    let hr = unsafe {
        EnclaveCopyIntoEnclave(vtl1_dest.as_mut_ptr() as _, vtl0_src as _, vtl1_dest.len())
    };
    check_hr(hr)?;

    Ok(())
}

pub fn copy_slice_out_of_enclave(vtl0_dest: *mut u8, vtl1_src: &[u8]) -> Result<(), EnclaveError> {
    let hr =
        unsafe { EnclaveCopyOutOfEnclave(vtl0_dest as _, vtl1_src.as_ptr() as _, vtl1_src.len()) };
    check_hr(hr)?;

    Ok(())
}

pub unsafe fn copy_into_enclave_unchecked<T: Copy>(vtl0_src: *const T) -> Result<T, EnclaveError> {
    let mut vtl1_buffer: Vec<u8> = Vec::new();
    vtl1_buffer.resize(core::mem::size_of::<T>(), 0);

    let hr = unsafe {
        EnclaveCopyIntoEnclave(
            vtl1_buffer.as_mut_ptr() as _,
            vtl0_src as _,
            core::mem::size_of::<T>(),
        )
    };

    check_hr(hr)?;

    Ok(unsafe { *(vtl1_buffer.as_ptr() as *const T) })
}

pub unsafe fn copy_out_of_enclave_unchecked<T>(
    vtl0_dest: *mut T,
    vtl1_src: &T,
) -> Result<(), EnclaveError> {
    let hr = unsafe {
        EnclaveCopyOutOfEnclave(
            vtl0_dest as _,
            vtl1_src as *const T as _,
            core::mem::size_of::<T>(),
        )
    };
    check_hr(hr)?;

    Ok(())
}

#[cfg(feature = "zerocopy")]
pub fn copy_into_enclave<T>(vtl0_src: *const T) -> Result<T, EnclaveError>
where
    T: zerocopy::TryFromBytes + zerocopy::KnownLayout + zerocopy::Immutable + Copy,
{
    let mut vtl1_buffer: Vec<u8> = Vec::new();
    vtl1_buffer.resize(core::mem::size_of::<T>(), 0);

    let hr = unsafe {
        EnclaveCopyIntoEnclave(
            vtl1_buffer.as_mut_ptr() as _,
            vtl0_src as _,
            core::mem::size_of::<T>(),
        )
    };
    check_hr(hr)?;

    match T::try_ref_from_bytes(&vtl1_buffer) {
        Ok(v) => Ok(*v),
        Err(_) => Err(EnclaveError::invalid_arg()),
    }
}

#[cfg(feature = "zerocopy")]
pub fn copy_out_of_enclave<T>(vtl0_dest: *mut T, vtl1_src: &T) -> Result<(), EnclaveError>
where
    T: zerocopy::KnownLayout + zerocopy::Immutable,
{
    let hr = unsafe {
        EnclaveCopyOutOfEnclave(
            vtl0_dest as _,
            vtl1_src as *const T as _,
            core::mem::size_of::<T>(),
        )
    };
    check_hr(hr)?;

    Ok(())
}
