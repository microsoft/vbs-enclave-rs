pub fn get_last_error() -> u32 {
    unsafe {
        windows_sys::Win32::Foundation::GetLastError()
    }
}
