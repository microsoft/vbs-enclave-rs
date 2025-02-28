#![no_std]
extern crate alloc;
use alloc::vec::Vec;

use spin::Mutex;
use vbs_enclave::{error::EnclaveError, winenclave::get_attestation_report};

use windows_sys::Win32::{
    Security::Cryptography::{
        BCryptBuffer, BCRYPT_AES_GCM_ALG_HANDLE, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION, BCRYPT_ECCKEY_BLOB, BCRYPT_ECCPUBLIC_BLOB,
        BCRYPT_ECDH_P256_ALG_HANDLE, BCRYPT_KDF_HASH, BCRYPT_KEY_DATA_BLOB,
        BCRYPT_KEY_DATA_BLOB_HEADER, BCRYPT_KEY_DATA_BLOB_MAGIC, BCRYPT_KEY_DATA_BLOB_VERSION1,
        BCRYPT_KEY_HANDLE, BCRYPT_SHA256_ALGORITHM, KDF_HASH_ALGORITHM,
    },
    System::Environment::ENCLAVE_REPORT_DATA_LENGTH,
};

mod bcrypt;
mod ffi;
mod params;

// A key handle is actually an alias of *const c_void but that
// isn't considered thread safe. Since it's an opaque handle,
// it's fine to convert it to a usize when storing it.
static KEYPAIR: Mutex<usize> = Mutex::new(0);
static KEY: Mutex<usize> = Mutex::new(0);

fn new_keypair_internal(key_size: u32, public_key_blob: &[u8]) -> Result<(), EnclaveError> {
    let mut key = KEY.lock();
    let mut keypair = KEYPAIR.lock();

    if *keypair != 0 || *key != 0 {
        return Err(EnclaveError::invalid_arg());
    }

    let algorithm = match key_size {
        256 => BCRYPT_ECDH_P256_ALG_HANDLE,
        _ => return Err(EnclaveError::invalid_arg()),
    };

    *keypair = bcrypt::generate_keypair(algorithm, key_size)? as usize;

    bcrypt::finalize_keypair(*keypair as BCRYPT_KEY_HANDLE)?;

    let public_key =
        bcrypt::import_keypair(algorithm, None, BCRYPT_ECCPUBLIC_BLOB, public_key_blob)?;

    let secret = bcrypt::secret_agreement(*keypair as BCRYPT_KEY_HANDLE, public_key)?;

    // This really should only fail if the key handle is invalid
    // but since we already used the key, we know it exists.
    let _ = bcrypt::destroy_key(public_key);

    // `pvBuffer` has to be a pointer to a UTF-16 C-string literal
    // and window-sys exports a *const u16 for the string literal,
    // but in the process of the conversion, the static length
    // is lost. Therefore, we have to calculate it ourselves.
    let mut parameters = [BCryptBuffer {
        cbBuffer: (("SHA256".len() + 1) * 2) as u32,
        BufferType: KDF_HASH_ALGORITHM,
        pvBuffer: BCRYPT_SHA256_ALGORITHM as *mut _,
    }];

    let derived_key = bcrypt::derive_key(secret, BCRYPT_KDF_HASH, &mut parameters)?;

    // This really should only fail if the key handle is invalid
    // but since we already used the key, we know it exists.
    let _ = bcrypt::destroy_key(secret);

    let mut key_blob = bcrypt::Aes256KeyBlob {
        header: BCRYPT_KEY_DATA_BLOB_HEADER {
            dwMagic: BCRYPT_KEY_DATA_BLOB_MAGIC,
            dwVersion: BCRYPT_KEY_DATA_BLOB_VERSION1,
            cbKeyData: bcrypt::AES256_KEY_SIZE as u32,
        },
        key_material: derived_key.try_into().expect(
            "A successful derive_key will always result in a Vec<u8> of length AES256_KEY_SIZE",
        ),
    };

    let aes_key = bcrypt::import_key(
        BCRYPT_AES_GCM_ALG_HANDLE,
        None,
        BCRYPT_KEY_DATA_BLOB,
        &mut key_blob,
    )?;

    *key = aes_key as usize;
    Ok(())
}

fn generate_report_internal() -> Result<Vec<u8>, EnclaveError> {
    let keypair = *KEYPAIR.lock() as BCRYPT_KEY_HANDLE;
    let public_key_blob = bcrypt::export_key(keypair, None, BCRYPT_ECCPUBLIC_BLOB)?;

    if public_key_blob.len() > size_of::<BCRYPT_ECCKEY_BLOB>() + ENCLAVE_REPORT_DATA_LENGTH as usize
    {
        return Err(EnclaveError::insufficient_buffer());
    }

    let mut data = [0u8; ENCLAVE_REPORT_DATA_LENGTH as usize];
    data.copy_from_slice(public_key_blob.split_at(size_of::<BCRYPT_ECCKEY_BLOB>()).1);

    get_attestation_report(Some(&data))
}

fn decrypt_data_internal(
    encrypted_data: &[u8],
    iv: &mut [u8],
    tag: &mut [u8],
) -> Result<Vec<u8>, EnclaveError> {
    let key = *KEY.lock() as BCRYPT_KEY_HANDLE;

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

    bcrypt::decrypt_aes_gcm(key, encrypted_data, &mode_info)
}
