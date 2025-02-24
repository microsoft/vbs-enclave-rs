#![no_std]
use core::ffi::c_void;

extern crate alloc;
use alloc::vec::Vec;

use spin::Mutex;
use vbs_enclave::{
    enclaveapi::call_enclave, error::EnclaveError, is_valid_vtl0, types::LPENCLAVE_ROUTINE,
    winenclave::get_attestation_report,
};

mod params;
use params::{DecryptDataParams, GenerateReportParams, NewKeypairParams};
use windows_sys::Win32::{
    Foundation::STATUS_SUCCESS,
    Security::Cryptography::{
        BCryptBuffer, BCryptBufferDesc, BCryptDecrypt, BCryptDeriveKey, BCryptExportKey,
        BCryptFinalizeKeyPair, BCryptGenerateKeyPair, BCryptImportKey, BCryptImportKeyPair,
        BCryptSecretAgreement, BCRYPTBUFFER_VERSION, BCRYPT_AES_GCM_ALG_HANDLE,
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
        BCRYPT_ECCKEY_BLOB, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDH_P256_ALG_HANDLE, BCRYPT_KDF_HASH,
        BCRYPT_KEY_DATA_BLOB, BCRYPT_KEY_DATA_BLOB_HEADER, BCRYPT_KEY_DATA_BLOB_MAGIC,
        BCRYPT_KEY_DATA_BLOB_VERSION1, BCRYPT_KEY_HANDLE, BCRYPT_SHA256_ALGORITHM,
        KDF_HASH_ALGORITHM,
    },
    System::Environment::ENCLAVE_REPORT_DATA_LENGTH,
};

mod ffi;

// A key handle is actually an alias of *const c_void but that
// isn't considered thread safe. Since it's an opaque handle,
// it's fine to convert it to a usize when storing it.
static KEYPAIR: Mutex<usize> = Mutex::new(0);
static KEY: Mutex<usize> = Mutex::new(0);

const AES256_KEY_SIZE: usize = 32;

#[repr(C)]
struct Aes256KeyBlob {
    header: BCRYPT_KEY_DATA_BLOB_HEADER,
    key_material: [u8; AES256_KEY_SIZE],
}

fn new_keypair_internal(
    params: NewKeypairParams,
    public_key_blob: &[u8],
) -> Result<(), EnclaveError> {
    let mut key_handle = core::ptr::null_mut::<c_void>();
    unsafe {
        let key_handle_ptr = &mut key_handle as *mut *mut c_void;
        let key_size = params.key_size;
        if BCryptGenerateKeyPair(
            match key_size {
                256 => BCRYPT_ECDH_P256_ALG_HANDLE,
                _ => return Err(EnclaveError::invalid_arg()),
            },
            key_handle_ptr,
            key_size,
            0u32,
        ) != STATUS_SUCCESS
        {
            return Err(EnclaveError::invalid_arg());
        }

        if BCryptFinalizeKeyPair(key_handle, 0) != STATUS_SUCCESS {
            return Err(EnclaveError::invalid_arg());
        }
    }

    let mut keypair = KEYPAIR.lock();

    if *keypair == 0 {
        *keypair = key_handle as usize;
    } else {
        return Err(EnclaveError::invalid_arg());
    }

    unsafe {
        let key_handle_ptr = &mut key_handle as *mut *mut c_void;
        let key_size = params.key_size;

        if BCryptImportKeyPair(
            match key_size {
                256 => BCRYPT_ECDH_P256_ALG_HANDLE,
                _ => return Err(EnclaveError::invalid_arg()),
            },
            core::ptr::null_mut(),
            BCRYPT_ECCPUBLIC_BLOB,
            key_handle_ptr,
            public_key_blob.as_ptr() as *const u8 as *const _,
            public_key_blob.len() as u32,
            0,
        ) != STATUS_SUCCESS
        {
            return Err(EnclaveError::invalid_arg());
        }

        let public_key = key_handle;

        let status =
            BCryptSecretAgreement(*keypair as BCRYPT_KEY_HANDLE, public_key, key_handle_ptr, 0);

        if status != STATUS_SUCCESS {
            return Err(EnclaveError { hresult: status });
        }

        let secret = key_handle;

        let mut buffer = BCryptBuffer {
            cbBuffer: (("SHA256".len() + 1) * 2) as u32,
            BufferType: KDF_HASH_ALGORITHM,
            pvBuffer: BCRYPT_SHA256_ALGORITHM as *mut _,
        };
        let parameter_list = BCryptBufferDesc {
            ulVersion: BCRYPTBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut buffer as *mut _,
        };

        let mut derived_key = Vec::new();
        derived_key.resize(AES256_KEY_SIZE, 0u8);

        let mut result: u32 = 0;

        let status = BCryptDeriveKey(
            secret,
            BCRYPT_KDF_HASH,
            &parameter_list as *const _,
            derived_key.as_mut_ptr(),
            AES256_KEY_SIZE as u32,
            &mut result as *mut u32,
            0,
        );

        if status != STATUS_SUCCESS {
            return Err(EnclaveError { hresult: status });
        }

        let mut key_blob = Aes256KeyBlob {
            header: BCRYPT_KEY_DATA_BLOB_HEADER {
                dwMagic: BCRYPT_KEY_DATA_BLOB_MAGIC,
                dwVersion: BCRYPT_KEY_DATA_BLOB_VERSION1,
                cbKeyData: AES256_KEY_SIZE as u32,
            },
            key_material: derived_key.try_into().unwrap(),
        };

        let status = BCryptImportKey(
            BCRYPT_AES_GCM_ALG_HANDLE,
            core::ptr::null_mut(),
            BCRYPT_KEY_DATA_BLOB,
            key_handle_ptr,
            core::ptr::null_mut(),
            0,
            &mut key_blob as *mut Aes256KeyBlob as *mut _,
            size_of_val(&key_blob) as u32,
            0,
        );

        if status != STATUS_SUCCESS {
            return Err(EnclaveError { hresult: status });
        }
    }

    let mut key = KEY.lock();

    if *key == 0 {
        *key = key_handle as _;
        Ok(())
    } else {
        Err(EnclaveError::invalid_arg())
    }
}

fn generate_report_internal(params: &mut GenerateReportParams) -> Result<(), EnclaveError> {
    let keypair = *KEYPAIR.lock() as BCRYPT_KEY_HANDLE;
    let mut public_key_blob: Vec<u8> = Vec::new();

    unsafe {
        let mut bytes_needed = 0u32;
        if BCryptExportKey(
            keypair,
            core::ptr::null_mut(),
            BCRYPT_ECCPUBLIC_BLOB,
            core::ptr::null_mut(),
            0,
            &mut bytes_needed,
            0,
        ) != STATUS_SUCCESS
        {
            return Err(EnclaveError::invalid_arg());
        }

        if bytes_needed > size_of::<BCRYPT_ECCKEY_BLOB>() as u32 + ENCLAVE_REPORT_DATA_LENGTH {
            return Err(EnclaveError::insufficient_buffer());
        }

        public_key_blob.resize(
            size_of::<BCRYPT_ECCKEY_BLOB>() + ENCLAVE_REPORT_DATA_LENGTH as usize,
            0,
        );

        if BCryptExportKey(
            keypair,
            core::ptr::null_mut(),
            BCRYPT_ECCPUBLIC_BLOB,
            public_key_blob.as_mut_ptr(),
            public_key_blob.len() as u32,
            &mut bytes_needed,
            0,
        ) != STATUS_SUCCESS
        {
            return Err(EnclaveError::invalid_arg());
        }
    }

    let mut data = [0u8; ENCLAVE_REPORT_DATA_LENGTH as usize];
    data.copy_from_slice(public_key_blob.split_at(size_of::<BCRYPT_ECCKEY_BLOB>()).1);

    let report = get_attestation_report(Some(&data))?;

    let mut allocation: *mut u8 = core::ptr::null_mut();
    unsafe {
        call_enclave(
            params.allocate_callback as LPENCLAVE_ROUTINE,
            report.len() as *mut _,
            true,
            &mut allocation as *mut *mut u8 as *mut *mut c_void,
        )?;

        if is_valid_vtl0(allocation as *const _, report.len()) {
            let data_vtl0: &mut [u8] = core::slice::from_raw_parts_mut(allocation, report.len());
            data_vtl0.copy_from_slice(&report);
        } else {
            return Err(EnclaveError::invalid_arg());
        }
    }

    params.report_size = report.len();
    params.report = allocation;

    Ok(())
}

fn decrypt_data_internal(
    params: &mut DecryptDataParams,
    encrypted_data: &[u8],
    tag: &mut [u8],
) -> Result<(), EnclaveError> {
    let key = *KEY.lock() as BCRYPT_KEY_HANDLE;

    let mut iv = [0u8; 12];

    let mode_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
        dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
        pbNonce: iv.as_mut_ptr() as *mut _,
        cbNonce: iv.len() as u32,
        pbAuthData: core::ptr::null_mut(),
        cbAuthData: 0,
        pbTag: tag.as_mut_ptr() as *mut _,
        cbTag: tag.len() as u32,
        pbMacContext: core::ptr::null_mut(),
        cbMacContext: 0,
        cbAAD: 0,
        cbData: 0,
        dwFlags: 0,
    };

    let mode_info_ptr = &mode_info as *const _;
    let mut decrypted_size = 0u32;

    let status = unsafe {
        BCryptDecrypt(
            key,
            encrypted_data.as_ptr(),
            encrypted_data.len() as u32,
            mode_info_ptr as *const _,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            0,
            &mut decrypted_size,
            0,
        )
    };

    if status != STATUS_SUCCESS {
        return Err(EnclaveError { hresult: status });
    }

    let mut decrypted_data: Vec<u8> = Vec::new();
    decrypted_data.resize(decrypted_size as usize, 0u8);

    let status = unsafe {
        BCryptDecrypt(
            key,
            encrypted_data.as_ptr(),
            encrypted_data.len() as u32,
            mode_info_ptr as *const _,
            core::ptr::null_mut(),
            0,
            decrypted_data.as_mut_ptr() as *mut _,
            decrypted_data.len() as u32,
            &mut decrypted_size,
            0,
        )
    };

    if status != STATUS_SUCCESS {
        return Err(EnclaveError { hresult: status });
    }

    let mut allocation: *mut u8 = core::ptr::null_mut();
    unsafe {
        call_enclave(
            params.allocate_callback as LPENCLAVE_ROUTINE,
            decrypted_data.len() as *mut _,
            true,
            &mut allocation as *mut *mut u8 as *mut *mut c_void,
        )?;

        if is_valid_vtl0(allocation as *const _, decrypted_data.len()) {
            let data_vtl0: &mut [u8] =
                core::slice::from_raw_parts_mut(allocation, decrypted_data.len());
            data_vtl0.copy_from_slice(&decrypted_data);
        } else {
            return Err(EnclaveError::invalid_arg());
        }
    }

    params.decrypted_data = allocation;
    params.decrypted_size = decrypted_data.len();

    Ok(())
}
