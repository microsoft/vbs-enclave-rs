# VBS Rust Enclave Example

This proof-of-concept demonstrates how one can implement a Windows [Virtualization-based security (VBS) enclave](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves) in Rust.

This project is the result of a Microsoft Offensive Research & Security Engineering (MORSE) hackathon.

## What does the sample do?

This sample enclave simulates an enclave that would operate on an untrusted remote system to create a shared secret between the enclave and a trusted remote system. In a realistic scenario, the host process would not be the one generating and deriving secrets; this would occur on the trusted remote system that uses the [Microsoft Azure Attestation service](https://learn.microsoft.com/en-us/azure/attestation/overview) or another service to validate the enclave's attestation claims before negotiating a shared secret.

The enclave has three exported routines:
- `new_keypair`: This routine accepts an ECDH public key from the host process, and then generates its own ECDH keypair. Once it has both, it derives a shared secret that can be used as an AES-GCM encryption key.
- `generate_report`: This routine accepts an allocation callback, which it uses to allocate space in the host process where it can write an attestation report containing its ECDH public key.
- `decrypt_data`: This routine accepts an allocation callback and ciphertext, which it then decrypts. It uses the allocation callback to allocate space in the host process where it can write the decrypted data.

Using these routines, the host process then performs the following actions:
- Generate an ECDH keypair
- Pass its public key to the enclave via `new_keypair`
- Request an attestation report via `generate_report`
- (Pretends to) validate the attestation report
- Extract the enclave's public key from the report
- Derive the shared secret using its private key and the enclave's public key
- Use the shared secret as an AES-GCM key encrypt a string provided in the command line
- Pass the resulting ciphertext to the enclave via `decrypt_data` and receive back the decrypted data
- Verify that the decrypted data matches the original plaintext and therefore round-tripped

## Requirements

- Rustlang 1.86.0-nightly
- Cargo
- Visual Studio 2022
- Windows 11 SDK (10.0.26100.0)

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

```
cd sample
cargo build
veiid.exe .\target\debug\sample_vbs_enclave_rs.dll

# Replace "MyTestEnclaveCert" with your test signing certificate's name
signtool.exe sign /ph /fd SHA256 /n "MyTestEnclaveCert" target\debug\sample_vbs_enclave_rs.dll
```

#### Release build

```
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
