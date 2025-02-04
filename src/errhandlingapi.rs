extern "system" {
    fn GetLastError() -> u32;
}

pub fn get_last_error() -> u32 {
    unsafe { GetLastError() }
}