use std::env;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::str;

const PROGRAM_FILES_X86: &str = "ProgramFiles(x86)";
const VCTOOLS_DEFAULT_PATH: &str = "VC\\Auxiliary\\Build\\Microsoft.VCToolsVersion.default.txt";
const MSVC_PATH: &str = "VC\\Tools\\MSVC";
const ENCLAVE_LIB_PATH: &str = "lib\\x64\\enclave";
const UCRT_LIB_PATH: &str = "ucrt_enclave\\x64\\ucrt.lib";

const SDK_SCRIPT: &str = r#"& {
    $kits_root_10 = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows Kits\Installed Roots\" -Name KitsRoot10).KitsRoot10
    $sdk_version = (Get-ChildItem -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows Kits\Installed Roots\" | Sort-Object -Descending)[0] | Split-Path -Leaf
    Write-Host "$($kits_root_10)Lib\$sdk_version"
}
"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rustc-link-arg=/OPT:REF,ICF");
    println!("cargo::rustc-link-arg=/ENTRY:dllmain");
    println!("cargo::rustc-link-arg=/MERGE:.edata=.rdata");
    println!("cargo::rustc-link-arg=/MERGE:.rustc=.data");
    println!("cargo::rustc-link-arg=/INTEGRITYCHECK");
    println!("cargo::rustc-link-arg=/enclave");
    println!("cargo::rustc-link-arg=/GUARD:MIXED");
    println!("cargo::rustc-link-arg=/include:__enclave_config");

    let program_files_x86 =
        env::var(PROGRAM_FILES_X86).expect("Program Files (x86) path not in environment variables");

    let powershell_output = Command::new("powershell.exe")
        .arg(SDK_SCRIPT)
        .output()?
        .stdout;
    let sdk_path = str::from_utf8(&powershell_output)?
        .trim();

    println!("{}", sdk_path);

    let vswhere =
        Path::new(&program_files_x86).join("Microsoft Visual Studio\\Installer\\vswhere.exe");

    let vswhere_output = Command::new(vswhere)
        .args([
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ])
        .output()?
        .stdout;

    let install_path = Path::new(
        str::from_utf8(&vswhere_output)?
            .trim(),
    );

    let mut default_path = String::new();
    std::fs::File::open(install_path.join(VCTOOLS_DEFAULT_PATH))
        .expect("Could not open Microsoft.VCToolsVersion.default.txt")
        .read_to_string(&mut default_path)?;

    let msvc = install_path.join(MSVC_PATH).join(default_path.trim());

    let enclave_lib_path = msvc.join(ENCLAVE_LIB_PATH);

    println!(
        "cargo::rustc-link-arg={}",
        Path::new(sdk_path)
            .join(UCRT_LIB_PATH)
            .to_str()
            .expect("Couldn't make string from ucrt.lib path")
    );
    // libvcruntime must come before vertdll or there will be duplicate external errors
    println!(
        "cargo::rustc-link-arg={}",
        enclave_lib_path
            .join("libvcruntime.lib")
            .to_str()
            .expect("Couldn't make string from libvcruntime.lib path")
    );
    println!(
        "cargo::rustc-link-arg={}",
        enclave_lib_path
            .join("libcmt.lib")
            .to_str()
            .expect("Couldn't make string from libcmt.lib path")
    );
    println!("cargo::rustc-link-arg=vertdll.lib");
    println!("cargo::rustc-link-arg=bcrypt.lib");

    Ok(())
}
