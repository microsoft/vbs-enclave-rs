use core::ffi::c_void;

use alloc::vec::Vec;
use vbs_enclave::error::{hresult_from_nt, EnclaveError};
use windows_sys::Win32::{
    Foundation::STATUS_SUCCESS,
    Security::Cryptography::{
        BCryptBuffer, BCryptBufferDesc, BCryptDecrypt, BCryptDeriveKey, BCryptDestroyKey,
        BCryptExportKey, BCryptFinalizeKeyPair, BCryptGenerateKeyPair, BCryptImportKey,
        BCryptImportKeyPair, BCryptSecretAgreement, BCRYPTBUFFER_VERSION, BCRYPT_ALG_HANDLE,
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO, BCRYPT_KEY_DATA_BLOB_HEADER, BCRYPT_KEY_HANDLE,
    },
};

pub const AES256_KEY_SIZE: usize = 32;

pub trait PaddingInfo {}

impl PaddingInfo for BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {}

pub trait KeyBlob {
    fn size(&self) -> u32;
}

#[repr(C)]
pub struct Aes256KeyBlob {
    pub header: BCRYPT_KEY_DATA_BLOB_HEADER,
    pub key_material: [u8; AES256_KEY_SIZE],
}

impl KeyBlob for Aes256KeyBlob {
    fn size(&self) -> u32 {
        size_of::<Self>() as u32
    }
}

pub fn generate_keypair(
    algorithm: BCRYPT_ALG_HANDLE,
    key_size: u32,
) -> Result<BCRYPT_KEY_HANDLE, EnclaveError> {
    let mut key_handle = core::ptr::null_mut::<c_void>();
    let key_handle_ptr = &mut key_handle as *mut *mut c_void;

    unsafe {
        // No flags defined. dwflags is always 0.
        match BCryptGenerateKeyPair(algorithm, key_handle_ptr, key_size, 0u32) {
            0 => Ok(key_handle),
            e => Err(EnclaveError {
                hresult: hresult_from_nt(e),
            }),
        }
    }
}

pub fn finalize_keypair(key: BCRYPT_KEY_HANDLE) -> Result<(), EnclaveError> {
    unsafe {
        // No flags defined. dwflags is always 0.
        match BCryptFinalizeKeyPair(key, 0) {
            0 => Ok(()),
            e => Err(EnclaveError {
                hresult: hresult_from_nt(e),
            }),
        }
    }
}

pub fn import_keypair(
    algorithm: BCRYPT_ALG_HANDLE,
    import_key: Option<BCRYPT_KEY_HANDLE>,
    blob_type: *const u16,
    input: &[u8],
) -> Result<BCRYPT_KEY_HANDLE, EnclaveError> {
    let Ok(input_size) = u32::try_from(input.len()) else {
        return Err(EnclaveError::invalid_arg());
    };

    let mut key_handle = core::ptr::null_mut::<c_void>();
    let key_handle_ptr = &mut key_handle as *mut *mut c_void;

    unsafe {
        // No flags defined, dwflags is always 0.
        match BCryptImportKeyPair(
            algorithm,
            if let Some(i) = import_key {
                i
            } else {
                core::ptr::null_mut()
            },
            blob_type,
            key_handle_ptr,
            input.as_ptr() as *const _,
            input_size,
            0,
        ) {
            STATUS_SUCCESS => Ok(key_handle),
            e => Err(EnclaveError {
                hresult: hresult_from_nt(e),
            }),
        }
    }
}

pub fn secret_agreement(
    private_key: BCRYPT_KEY_HANDLE,
    public_key: BCRYPT_KEY_HANDLE,
) -> Result<BCRYPT_KEY_HANDLE, EnclaveError> {
    let mut key_handle = core::ptr::null_mut::<c_void>();
    let key_handle_ptr = &mut key_handle as *mut *mut c_void;

    unsafe {
        // No flags defined, dwflags is always 0.
        match BCryptSecretAgreement(private_key, public_key, key_handle_ptr, 0) {
            STATUS_SUCCESS => Ok(key_handle),
            e => Err(EnclaveError {
                hresult: hresult_from_nt(e),
            }),
        }
    }
}

pub fn derive_key(
    shared_secret: BCRYPT_KEY_HANDLE,
    kdf: *const u16,
    parameters: &mut [BCryptBuffer],
) -> Result<Vec<u8>, EnclaveError> {
    let mut derived_key: Vec<u8> = Vec::new();

    let parameter_list = BCryptBufferDesc {
        ulVersion: BCRYPTBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: parameters.as_mut_ptr() as *mut _,
    };

    let mut size_needed = 0u32;

    unsafe {
        // No flags defined, dwflags is always 0.
        match BCryptDeriveKey(
            shared_secret,
            kdf,
            &parameter_list as *const _,
            core::ptr::null_mut(),
            0u32,
            &mut size_needed as *mut u32,
            0,
        ) {
            STATUS_SUCCESS => {}
            e => {
                return Err(EnclaveError {
                    hresult: hresult_from_nt(e),
                })
            }
        }
    }

    derived_key.resize(size_needed as usize, 0u8);

    unsafe {
        // No flags defined, dwflags is always 0.
        match BCryptDeriveKey(
            shared_secret,
            kdf,
            &parameter_list as *const _,
            derived_key.as_mut_ptr() as *mut _,
            derived_key.len() as u32,
            &mut size_needed as *mut u32,
            0,
        ) {
            STATUS_SUCCESS => Ok(derived_key),
            e => Err(EnclaveError {
                hresult: hresult_from_nt(e),
            }),
        }
    }
}

pub fn import_key(
    algorithm: BCRYPT_ALG_HANDLE,
    import_key: Option<BCRYPT_KEY_HANDLE>,
    blob_type: *const u16,
    input: &mut dyn KeyBlob,
) -> Result<BCRYPT_KEY_HANDLE, EnclaveError> {
    let mut key_handle = core::ptr::null_mut::<c_void>();
    let key_handle_ptr = &mut key_handle as *mut *mut c_void;

    unsafe {
        // No flags defined, dwflags is always 0.
        // Ignoring the key object parameters, this sample will never use them.
        match BCryptImportKey(
            algorithm,
            if let Some(i) = import_key {
                i
            } else {
                core::ptr::null_mut()
            },
            blob_type,
            key_handle_ptr,
            core::ptr::null_mut(),
            0,
            input as *mut _ as *mut _,
            input.size() as u32,
            0,
        ) {
            STATUS_SUCCESS => Ok(key_handle),
            e => Err(EnclaveError {
                hresult: hresult_from_nt(e),
            }),
        }
    }
}

pub fn export_key(
    key: BCRYPT_KEY_HANDLE,
    export_key: Option<BCRYPT_KEY_HANDLE>,
    blob_type: *const u16,
) -> Result<Vec<u8>, EnclaveError> {
    let mut key_blob: Vec<u8> = Vec::new();
    let mut bytes_needed = 0u32;

    unsafe {
        // No flags defined, dwflags is always 0.
        match BCryptExportKey(
            key,
            if let Some(e) = export_key {
                e
            } else {
                core::ptr::null_mut()
            },
            blob_type,
            core::ptr::null_mut(),
            0,
            &mut bytes_needed,
            0,
        ) {
            STATUS_SUCCESS => {}
            e => {
                return Err(EnclaveError {
                    hresult: hresult_from_nt(e),
                })
            }
        }
    }

    key_blob.resize(bytes_needed as usize, 0u8);

    unsafe {
        match BCryptExportKey(
            key,
            if let Some(e) = export_key {
                e
            } else {
                core::ptr::null_mut()
            },
            blob_type,
            key_blob.as_mut_ptr(),
            key_blob.len() as u32,
            &mut bytes_needed,
            0,
        ) {
            STATUS_SUCCESS => Ok(key_blob),
            e => Err(EnclaveError {
                hresult: hresult_from_nt(e),
            }),
        }
    }
}

pub fn decrypt(
    key: BCRYPT_KEY_HANDLE,
    encrypted_data: &[u8],
    padding_info: Option<&dyn PaddingInfo>,
    iv: Option<&mut [u8]>,
    flags: u32,
) -> Result<Vec<u8>, EnclaveError> {
    let mut decrypted_size = 0u32;

    let (iv, iv_size) = match iv {
        Some(i) => (i.as_mut_ptr(), i.len() as u32),
        None => (core::ptr::null_mut(), 0),
    };

    unsafe {
        match BCryptDecrypt(
            key,
            encrypted_data.as_ptr(),
            encrypted_data.len() as u32,
            if let Some(p) = padding_info {
                p as *const _ as *const _
            } else {
                core::ptr::null()
            },
            iv,
            iv_size,
            core::ptr::null_mut(),
            0,
            &mut decrypted_size,
            flags,
        ) {
            STATUS_SUCCESS => {}
            e => {
                return Err(EnclaveError {
                    hresult: hresult_from_nt(e),
                })
            }
        }
    }

    let mut decrypted_data: Vec<u8> = Vec::new();
    decrypted_data.resize(decrypted_size as usize, 0u8);

    unsafe {
        match BCryptDecrypt(
            key,
            encrypted_data.as_ptr(),
            encrypted_data.len() as u32,
            if let Some(p) = padding_info {
                p as *const _ as *const _
            } else {
                core::ptr::null()
            },
            core::ptr::null_mut(),
            0,
            decrypted_data.as_mut_ptr() as *mut _,
            decrypted_data.len() as u32,
            &mut decrypted_size,
            flags,
        ) {
            STATUS_SUCCESS => Ok(decrypted_data),
            e => Err(EnclaveError {
                hresult: hresult_from_nt(e),
            }),
        }
    }
}

pub fn destroy_key(key: BCRYPT_KEY_HANDLE) -> Result<(), EnclaveError> {
    unsafe {
        match BCryptDestroyKey(key) {
            STATUS_SUCCESS => Ok(()),
            e => Err(EnclaveError {
                hresult: hresult_from_nt(e),
            }),
        }
    }
}
