#[repr(C)]
#[derive(Clone, Copy)]
pub struct NewKeypairParams {
    // Only 256 is supported, because it needs to fit into the report
    pub key_size: u32,
    pub public_key_blob: *const u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GenerateReportParams {
    pub allocate_callback: extern "C" fn(usize) -> *mut u8,
    pub report_size: usize,
    pub report: *const u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DecryptDataParams {
    pub allocate_callback: extern "C" fn(usize) -> *mut u8,
    pub encrypted_size: usize,
    pub encrypted_data: *const u8,
    pub tag_size: usize,
    pub tag: *const u8,
    pub decrypted_size: usize,
    pub decrypted_data: *const u8,
}
