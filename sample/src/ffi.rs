use alloc::vec::Vec;
use hex_literal::hex;
use vbs_enclave::enclaveapi::{call_enclave, EnclaveRoutineInvocation};
use vbs_enclave::error::{EnclaveError, HRESULT, S_OK};
use vbs_enclave::is_valid_vtl0;
use vbs_enclave::types::LPENCLAVE_ROUTINE;
use vbs_enclave::winenclave::{
    ImageEnclaveConfig, IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE, IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
};
use windows_sys::Win32::Security::Cryptography::BCRYPT_ECCKEY_BLOB;
use windows_sys::Win32::System::Environment::ENCLAVE_REPORT_DATA_LENGTH;

use crate::params::{DecryptDataParams, GenerateReportParams, NewKeypairParams};
use crate::{decrypt_data_internal, generate_report_internal, new_keypair_internal};

// You should only enable debug in debug builds, or it can allow someone to
// access your enclave in VTL0.
#[cfg(debug_assertions)]
const ENCLAVE_CONFIG_POLICY_FLAGS: u32 = vbs_enclave::winenclave::IMAGE_ENCLAVE_POLICY_DEBUGGABLE;
#[cfg(not(debug_assertions))]
const ENCLAVE_CONFIG_POLICY_FLAGS: u32 = 0;

// This structure is necessary for the enclave to load correctly.
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
    // The first thing that needs to happen is validating the NewKeypairParams
    // pointer is fully within vtl0 memory, then copy it into vtl1 memory.
    // This prevents time-of-check/time-of-use bugs that can arise if you
    // read values that are residing within vtl0.
    let params_vtl1 = if is_valid_vtl0(params_vtl0 as *const _, size_of::<NewKeypairParams>()) {
        unsafe { *params_vtl0 }
    } else {
        return EnclaveError::invalid_arg().into();
    };

    // Next, the public key buffer also lives in vtl0, so it needs to be
    // validated and copied into vtl1 as well.
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

    // Finally, we can call the internal function that only operates on
    // safe Rust objects.
    match new_keypair_internal(params_vtl1.key_size, &public_key_blob) {
        Ok(()) => S_OK,
        Err(e) => e.into(),
    }
}

#[no_mangle]
extern "C" fn generate_report(params_vtl0: *mut GenerateReportParams) -> HRESULT {
    // The first thing that needs to happen is validating the GenerateReportParams
    // pointer is fully within vtl0 memory, then copy it into vtl1 memory.
    // This prevents time-of-check/time-of-use bugs that can arise if you
    // read values that are residing within vtl0.
    let params_vtl1 = unsafe {
        if is_valid_vtl0(params_vtl0 as *const _, size_of::<GenerateReportParams>()) {
            *params_vtl0.clone()
        } else {
            return EnclaveError::invalid_arg().into();
        }
    };

    // Next, the callback pointer in the structure needs to be validated, otherwise
    // CallEnclave can call a function within our vtl1 enclave and that is bad.
    // Note that this pointer is checked in the vtl1 struct, not the vtl0 struct,
    // because if it were checked in the vtl0 struct, an attacker could change it
    // after it is checked but before it is used.
    if !is_valid_vtl0(params_vtl1.allocate_callback as *const _, 1) {
        return EnclaveError::invalid_arg().into();
    }

    // The internal function operated only on safe Rust objects. Any unsafe code
    // is in the FFI function like this one, or in a wrapper function for bcrypt
    // or enclave APIs.
    let report = match generate_report_internal() {
        Ok(v) => v,
        Err(e) => return e.into(),
    };

    // Once we have the report vector, we call the vtl0 allocation callback
    // and validate that the pointer we get back is valid before copying the
    // data out to it.
    let invocation = unsafe {
        EnclaveRoutineInvocation::new(
            params_vtl1.allocate_callback as LPENCLAVE_ROUTINE,
            report.len() as *const _,
        )
    };
    let allocation: *mut u8 = match call_enclave(invocation, true) {
        Ok(v) => v as *mut u8,
        Err(e) => return e.into(),
    };

    if is_valid_vtl0(allocation as *const _, report.len()) {
        unsafe {
            let data_vtl0: &mut [u8] = core::slice::from_raw_parts_mut(allocation, report.len());
            data_vtl0.copy_from_slice(&report);
        }
    } else {
        return EnclaveError::invalid_arg().into();
    }

    // Finally, now that we have copied the buffer out, we set the length and pointer
    // in the vtl0 structure (which we already know is a valid allocation) so that the
    // host process can continue.
    unsafe {
        (*params_vtl0).report_size = report.len();
        (*params_vtl0).report = allocation;
    }

    S_OK
}

#[no_mangle]
extern "C" fn decrypt_data(params_vtl0: *mut DecryptDataParams) -> HRESULT {
    // The first thing that needs to happen is validating the DecryptDataParams
    // pointer is fully within vtl0 memory, then copy it into vtl1 memory.
    // This prevents time-of-check/time-of-use bugs that can arise if you
    // read values that are residing within vtl0.
    let params_vtl1 = if is_valid_vtl0(params_vtl0 as *const _, size_of::<DecryptDataParams>()) {
        unsafe { *params_vtl0.clone() }
    } else {
        return EnclaveError::invalid_arg().into();
    };

    // Next, the callback pointer in the structure needs to be validated, otherwise
    // CallEnclave can call a function within our vtl1 enclave and that is bad.
    // Note that this pointer is checked in the vtl1 struct, not the vtl0 struct,
    // because if it were checked in the vtl0 struct, an attacker could change it
    // after it is checked but before it is used.
    if !is_valid_vtl0(params_vtl1.allocate_callback as *const _, 1) {
        return EnclaveError::invalid_arg().into();
    }

    // The encrypted data buffer also lives in vtl0, so it needs to be
    // validated and copied into vtl1 as well.
    let mut encrypted_data: Vec<u8> = Vec::new();
    encrypted_data.resize(params_vtl1.encrypted_size, 0u8);

    if is_valid_vtl0(
        (&params_vtl1).encrypted_data as *const u8 as *const _,
        (&params_vtl1).encrypted_size,
    ) {
        unsafe {
            encrypted_data
                .as_mut_slice()
                .copy_from_slice(core::slice::from_raw_parts(
                    params_vtl1.encrypted_data,
                    params_vtl1.encrypted_size,
                ));
        }
    } else {
        return EnclaveError::invalid_arg().into();
    }

    // The initialization vector buffer also lives in vtl0, so it needs to be
    // validated and copied into vtl1 as well.
    let mut iv: Vec<u8> = Vec::new();
    iv.resize(params_vtl1.iv_size, 0u8);

    if is_valid_vtl0(
        (&params_vtl1).iv as *const u8 as *const _,
        (&params_vtl1).iv_size,
    ) {
        unsafe {
            iv.as_mut_slice()
                .copy_from_slice(core::slice::from_raw_parts(
                    params_vtl1.iv,
                    params_vtl1.iv_size,
                ));
        }
    } else {
        return EnclaveError::invalid_arg().into();
    }

    // The authentication tag buffer also lives in vtl0, so it needs to be
    // validated and copied into vtl1 as well.
    let mut tag: Vec<u8> = Vec::new();
    tag.resize(params_vtl1.tag_size, 0u8);

    if is_valid_vtl0(
        (&params_vtl1).tag as *const u8 as *const _,
        (&params_vtl1).tag_size,
    ) {
        unsafe {
            tag.as_mut_slice()
                .copy_from_slice(core::slice::from_raw_parts(
                    params_vtl1.tag,
                    params_vtl1.tag_size,
                ));
        }
    } else {
        return EnclaveError::invalid_arg().into();
    }

    // The internal function operated only on safe Rust objects. Any unsafe code
    // is in the FFI function like this one, or in a wrapper function for bcrypt
    // or enclave APIs.
    let decrypted_data = match decrypt_data_internal(&encrypted_data, &mut iv, &mut tag) {
        Ok(v) => v,
        Err(e) => return e.into(),
    };

    // Once we have the plaintext vector, we call the vtl0 allocation callback
    // and validate that the pointer we get back is valid before copying the
    // data out to it.
    let invocation = unsafe {
        EnclaveRoutineInvocation::new(
            params_vtl1.allocate_callback as LPENCLAVE_ROUTINE,
            decrypted_data.len() as *const _,
        )
    };
    let allocation: *mut u8 = match call_enclave(invocation, true) {
        Ok(v) => v as *mut u8,
        Err(e) => return e.into(),
    };

    if is_valid_vtl0(allocation as *const _, decrypted_data.len()) {
        unsafe {
            let data_vtl0: &mut [u8] =
                core::slice::from_raw_parts_mut(allocation, decrypted_data.len());
            data_vtl0.copy_from_slice(&decrypted_data);
        }
    } else {
        return EnclaveError::invalid_arg().into();
    }

    // Finally, now that we have copied the buffer out, we set the length and pointer
    // in the vtl0 structure (which we already know is a valid allocation) so that the
    // host process can continue.
    unsafe {
        (*params_vtl0).decrypted_size = decrypted_data.len();
        (*params_vtl0).decrypted_data = allocation;
    }

    S_OK
}
