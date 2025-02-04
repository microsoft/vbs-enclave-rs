use core::mem::offset_of;

pub const ENCLAVE_LONG_ID_LENGTH: usize = 32;
pub const ENCLAVE_SHORT_ID_LENGTH: usize = 16;

pub const IMAGE_ENCLAVE_LONG_ID_LENGTH: usize = ENCLAVE_LONG_ID_LENGTH;
pub const IMAGE_ENCLAVE_SHORT_ID_LENGTH: usize = ENCLAVE_SHORT_ID_LENGTH;
pub const IMAGE_ENCLAVE_POLICY_DEBUGGABLE: u32 = 0x0000_0001;
pub const IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE: u32 = 0x0000_0001;

pub const ENCLAVE_FLAG_FULL_DEBUG_ENABLED: u32 = 0x0000_0001;

pub const ENCLAVE_FLAG_DYNAMIC_DEBUG_ENABLED: u32 = 0x0000_0002;

pub const ENCLAVE_FLAG_DYNAMIC_DEBUG_ACTIVE: u32 = 0x0000_0004;

// #pragma pack(1)
// typedef struct ENCLAVE_IDENTITY {
//     UINT8 OwnerId[IMAGE_ENCLAVE_LONG_ID_LENGTH];
//     UINT8 UniqueId[IMAGE_ENCLAVE_LONG_ID_LENGTH];
//     UINT8 AuthorId[IMAGE_ENCLAVE_LONG_ID_LENGTH];
//     UINT8 FamilyId[IMAGE_ENCLAVE_SHORT_ID_LENGTH];
//     UINT8 ImageId[IMAGE_ENCLAVE_SHORT_ID_LENGTH];
//     UINT32 EnclaveSvn;
//     UINT32 SecureKernelSvn;
//     UINT32 PlatformSvn;
//     UINT32 Flags;
//     UINT32 SigningLevel;
//     UINT32 EnclaveType;
// } ENCLAVE_IDENTITY;

#[repr(C)]
#[derive(Default)]
pub struct EnclaveIdentity {
    owner_id: [u8; IMAGE_ENCLAVE_LONG_ID_LENGTH],
    unique_id: [u8; IMAGE_ENCLAVE_LONG_ID_LENGTH],
    author_id: [u8; IMAGE_ENCLAVE_LONG_ID_LENGTH],
    family_id: [u8; IMAGE_ENCLAVE_SHORT_ID_LENGTH],
    image_id: [u8; IMAGE_ENCLAVE_SHORT_ID_LENGTH],
    enclave_svn: u32,
    secure_kernel_svn: u32,
    platform_svn: u32,
    flags: u32,
    signing_level: u32,
    enclave_type: u32,
}

impl EnclaveIdentity {
    pub fn owner_id(&self) -> &[u8] {
        &self.owner_id
    }

    pub fn unique_id(&self) -> &[u8] {
        &self.unique_id
    }

    pub fn author_id(&self) -> &[u8] {
        &self.author_id
    }

    pub fn family_id(&self) -> &[u8] {
        &self.family_id
    }

    pub fn image_id(&self) -> &[u8] {
        &self.image_id
    }

    pub fn enclave_svn(&self) -> u32 {
        self.enclave_svn
    }

    pub fn secure_kernel_svn(&self) -> u32 {
        self.secure_kernel_svn
    }

    pub fn platform_svn(&self) -> u32 {
        self.platform_svn
    }

    pub fn flags(&self) -> u32 {
        self.flags
    }

    pub fn signing_level(&self) -> u32 {
        self.signing_level
    }

    pub fn enclave_type(&self) -> u32 {
        self.enclave_type
    }
}

// typedef struct ENCLAVE_INFORMATION {
//     ULONG EnclaveType;
//     ULONG Reserved;
//     PVOID BaseAddress;
//     SIZE_T Size;
//     ENCLAVE_IDENTITY Identity;
// } ENCLAVE_INFORMATION;

#[repr(C)]
#[derive(Default)]
pub struct EnclaveInformation {
    enclave_type: u32,
    reserved: u32,
    base_address: usize,
    size: usize,
    identity: EnclaveIdentity,
}

impl EnclaveInformation {
    pub fn enclave_type(&self) -> u32 {
        self.enclave_type
    }

    pub fn base_address(&self) -> usize {
        self.base_address
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn identity(&self) -> &EnclaveIdentity {
        &self.identity
    }
}

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

extern "system" {
    fn EnclaveGetEnclaveInformation(
        information_size: u32,
        enclave_information: *mut EnclaveInformation,
    ) -> NativeHResult;

    // BOOL CallEnclave(
    //     [in]  LPENCLAVE_ROUTINE lpRoutine,
    //     [in]  LPVOID            lpParameter,
    //     [in]  BOOL              fWaitForThread,
    //     [out] LPVOID            *lpReturnValue
    //   );
    // fn CallEnclave(routine: usize, parameter: usize, wait_for_thread: bool, return_value: &mut usize) -> bool;

    fn GetLastError() -> u32;
}

pub fn get_enclave_information(enclave_information: &mut EnclaveInformation) -> HResult {
    unsafe {
        match EnclaveGetEnclaveInformation(
            size_of::<EnclaveInformation>() as u32,
            enclave_information as *mut _,
        ) {
            0 => Ok(HResultSuccess::Ok),
            e => Err(e),
        }
    }
}

pub fn get_last_error() -> u32 {
    unsafe { GetLastError() }
}
