# VBS Rust Enclave Example

This proof-of-concept demonstrates how one can implement a Windows [Virtualization-based security (VBS) enclave](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves) in Rust.

This project is the result of a Microsoft Offensive Research & Security Engineering (MORSE) hackathon.

## Requirements

- [Rustlang](https://www.rust-lang.org/tools/install) 1.86.0-nightly
- Cargo
- [Visual Studio 2022](https://visualstudio.microsoft.com/downloads/)
- [Windows 11 SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) (10.0.22621.3233 or later)

It was tested on x86_64, but will probably build for arm64 with no issues.

## Building the `vbs-enclave` crate

The `vbs-enclave` crate will build with `cargo build` just fine. However, this crate only builds an rlib and is not usable standalone, but there is a sample enclave using it provided.

## Building the Sample

### `SampleHost`

The sample host executable, `SampleHost.exe` is a Visual Studio project. Ensure the configuration you select (Debug or Release) matches what you build the enclave DLL for.  

### `sample-vbs-enclave-rs`

#### Test Signing
Prior to building, follow the steps in the [VBS Enclaves Development Guide](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves-dev-guide#step-3-signing-vbs-enclave-dlls) for configuring test signing. Export your certificate to a file (in these instructions, we use `enclave.cer`)

You will probably want to run the sample on a test system, since it requires test signing. When you set up your test system, ensure that VBS is enabled. The instructions below work for a Hyper-V VM:

On your host system, in an administrator prompt, run:
```powershell
Set-VMProcessor -VmName "My VM Name" -ExposeVirtualizationExtensions $true
```

On your test system VM, run:
```powershell
bcdedit /set testsigning on
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 1 /f
Restart-Computer
```

Additionally, you will need to copy your test signing certificate to the test system and install it:

```powershell
Set-Location -Path Cert:\CurrentUser\My
Import-Certificate C:\enclave.cer 
```

Once you have a test signing certificate created and have enabled test signing on the system that will run the example enclave, you can build the enclave itself from the Visual Studio command prompt:

#### Debug build

```powershell
cd sample
cargo build
veiid.exe .\target\debug\sample_vbs_enclave_rs.dll

# Replace "MyTestEnclaveCert" with your test signing certificate's name
signtool.exe sign /ph /fd SHA256 /n "MyTestEnclaveCert" target\debug\sample_vbs_enclave_rs.dll
```

#### Release build

```powershell
cd sample
cargo build -r
veiid.exe .\target\release\sample_vbs_enclave_rs.dll

# Replace "MyTestEnclaveCert" with your test signing certificate's name
signtool.exe sign /ph /fd SHA256 /n "MyTestEnclaveCert" target\release\sample_vbs_enclave_rs.dll
```

## Running the sample

Once you have the sample host and enclave executables, you can launch it like so, with this example output:

```
> .\SampleHost.exe .\sample_vbs_enclave_rs.dll "Hello World"
Rust enclave created and initialized!
Creating host keypair...
Creating new enclave key and providing host public key...
New keypair created!
Report generated! 1240 bytes!
Beep boop beep, validating attestation report... (for pretend)
Enclave is validated!
Deriving shared key...
Public key imported successfully!
Successfully derived shared ephemeral key!
Encrypting the message:
48 00 65 00 6c 00 6c 00 6f 00 20 00 57 00 6f 00 H.e.l.l.o...W.o.
72 00 6c 00 64 00                               r.l.d.

Data decrypted! Message is:
48 00 65 00 6c 00 6c 00 6f 00 20 00 57 00 6f 00 H.e.l.l.o...W.o.
72 00 6c 00 64 00                               r.l.d.

The message round-tripped!
```

## Future
- Develop safe wrappers for VTL0 pointers and other mechanisms to ensure secure pointer usage across the VTL0<->VTL1 trust boundary
- Use bindgen to generate parameter structures used in the host process from its header files
- Implement a Rust version of SampleHost too

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
