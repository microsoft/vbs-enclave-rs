use alloc::vec::Vec;
use hex_literal::hex;
use vbs_enclave::error::{EnclaveError, HRESULT, S_OK};
use vbs_enclave::is_valid_vtl0;
use vbs_enclave::winenclave::{
    ImageEnclaveConfig, IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE, IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
};
use windows_sys::Win32::Security::Cryptography::BCRYPT_ECCKEY_BLOB;
use windows_sys::Win32::System::Environment::ENCLAVE_REPORT_DATA_LENGTH;

use crate::params::{DecryptDataParams, GenerateReportParams, NewKeypairParams};
use crate::{decrypt_data_internal, generate_report_internal, new_keypair_internal};

#[cfg(debug_assertions)]
const ENCLAVE_CONFIG_POLICY_FLAGS: u32 = vbs_enclave::winenclave::IMAGE_ENCLAVE_POLICY_DEBUGGABLE;
#[cfg(not(debug_assertions))]
const ENCLAVE_CONFIG_POLICY_FLAGS: u32 = 0;

#[no_mangle]
#[allow(
    non_upper_case_globals,
    reason = "__enclave_config is a special name required for enclaves"
)]
pub static __enclave_config: ImageEnclaveConfig = ImageEnclaveConfig {
    size: size_of::<ImageEnclaveConfig>() as u32,
    // This value just points to the the offset of enclave_flags
    minimum_required_config_size: IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
    policy_flags: ENCLAVE_CONFIG_POLICY_FLAGS,
    number_of_imports: 0,
    import_list: 0,
    import_entry_size: 0,
    family_id: hex!(
        "fefe0000 00000000"
        "00000000 00000000"
    ),
    image_id: hex!(
        "01010000 00000000"
        "00000000 00000000"
    ),
    image_version: 0,
    security_version: 0,
    enclave_size: 0x1000_0000,
    number_of_threads: 16,
    enclave_flags: IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE,
};

#[no_mangle]
extern "C" fn new_keypair(params_vtl0: *const NewKeypairParams) -> HRESULT {
    let params_vtl1 = if is_valid_vtl0(params_vtl0 as *const _, size_of::<NewKeypairParams>()) {
        unsafe { *params_vtl0 }
    } else {
        return EnclaveError::invalid_arg().into();
    };

    let public_key_blob_size =
        size_of::<BCRYPT_ECCKEY_BLOB>() + ENCLAVE_REPORT_DATA_LENGTH as usize;
    let mut public_key_blob = Vec::new();
    public_key_blob.resize(public_key_blob_size, 0u8);

    if is_valid_vtl0(
        (&params_vtl1).public_key_blob as *const u8 as *const _,
        public_key_blob_size,
    ) {
        unsafe {
            public_key_blob
                .as_mut_slice()
                .copy_from_slice(core::slice::from_raw_parts(
                    params_vtl1.public_key_blob,
                    public_key_blob_size,
                ));
        }
    } else {
        return EnclaveError::invalid_arg().into();
    }

    match new_keypair_internal(params_vtl1, &public_key_blob) {
        Ok(()) => S_OK,
        Err(e) => e.into(),
    }
}

#[no_mangle]
extern "C" fn generate_report(params_vtl0: *mut GenerateReportParams) -> HRESULT {
    let mut params_vtl1 = unsafe {
        if is_valid_vtl0(params_vtl0 as *const _, size_of::<GenerateReportParams>()) {
            *params_vtl0.clone()
        } else {
            return EnclaveError::invalid_arg().into();
        }
    };

    if !is_valid_vtl0(params_vtl1.allocate_callback as *const _, 1) {
        return EnclaveError::invalid_arg().into();
    }

    if let Err(e) = generate_report_internal(&mut params_vtl1) {
        return e.into();
    }

    unsafe {
        (*params_vtl0).report_size = params_vtl1.report_size;
        (*params_vtl0).report = params_vtl1.report;
    }

    S_OK
}

#[no_mangle]
extern "C" fn decrypt_data(params_vtl0: *mut DecryptDataParams) -> HRESULT {
    let mut params_vtl1 = unsafe {
        if is_valid_vtl0(params_vtl0 as *const _, size_of::<DecryptDataParams>()) {
            *params_vtl0.clone()
        } else {
            return EnclaveError::invalid_arg().into();
        }
    };

    let mut encrypted_data: Vec<u8> = Vec::new();
    encrypted_data.resize(params_vtl1.encrypted_size, 0u8);

    unsafe {
        if is_valid_vtl0(
            (&params_vtl1).encrypted_data as *const u8 as *const _,
            (&params_vtl1).encrypted_size,
        ) {
            encrypted_data
                .as_mut_slice()
                .copy_from_slice(core::slice::from_raw_parts(
                    params_vtl1.encrypted_data,
                    params_vtl1.encrypted_size,
                ));
        } else {
            return EnclaveError::invalid_arg().into();
        }
    }

    let mut tag: Vec<u8> = Vec::new();
    tag.resize(params_vtl1.tag_size, 0u8);

    unsafe {
        if is_valid_vtl0(
            (&params_vtl1).tag as *const u8 as *const _,
            (&params_vtl1).tag_size,
        ) {
            tag.as_mut_slice()
                .copy_from_slice(core::slice::from_raw_parts(
                    params_vtl1.tag,
                    params_vtl1.tag_size,
                ));
        } else {
            return EnclaveError::invalid_arg().into();
        }
    }

    if let Err(e) = decrypt_data_internal(&mut params_vtl1, &encrypted_data, &mut tag) {
        return e.into();
    }

    unsafe {
        (*params_vtl0).decrypted_size = params_vtl1.decrypted_size;
        (*params_vtl0).decrypted_data = params_vtl1.decrypted_data;
    }

    S_OK
}
