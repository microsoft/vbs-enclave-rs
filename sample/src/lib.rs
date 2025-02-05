#![no_std]

use hex_literal::hex;

use vbs_enclave::types::VTL0Ptr;
use vbs_enclave::{HResult, HResultError, HResultSuccess, NativeHResult};
use vbs_enclave::winenclave::{
    ImageEnclaveConfig,
    IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE,
    IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
};

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

mod params;
use params::*;

#[no_mangle]
extern "C" fn my_enclave_function(param: VTL0Ptr<MyEnclaveParams>) -> NativeHResult {
    let mut params = match param.try_into() {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Alternatively, if you want typing explicit:
    // let mut params = match VTL1MyEnclaveParams::try_from(param) {
    //     Ok(p) => p,
    //     Err(e) => return e,
    // };

    match my_enclave_function_safe(&mut params) {
        Ok(s) => s,
        Err(e) => e,
    }
}

fn my_enclave_function_safe(params: &mut VTL1MyEnclaveParams) -> HResult {
    if params.a + params.b != params.c {
        return Err(HResultError::InvalidState as _);
    }

    *params.e = params.d.iter().sum();

    Ok(HResultSuccess::Ok as _)
}
