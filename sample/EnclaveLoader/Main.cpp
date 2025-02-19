#include <winenclave.h>
#include <cstdint>
#include <iostream>
#include <string>

const uint8_t OwnerId[IMAGE_ENCLAVE_LONG_ID_LENGTH] = {0x10, 0x20, 0x30, 0x40, 0x41, 0x31, 0x21, 0x11};

// template<typename T>
// struct VTL0Array {
//	_In_ T* arr;
//	_In_ size_t count;
// };
//
// struct MyEnclaveParams {
//	_In_ uint32_t a;
//	_In_ uint32_t b;
//	_In_ uint32_t* c;
//	_In_ VTL0Array<uint32_t> d;
//	_Out_ uint32_t* e;
// };

struct NewKeypairParams
{
	uint32_t key_size;
	uint8_t* public_key;

};

struct GenerateReportParams
{
	uint8_t *(*allocate_callback)(size_t);
	size_t report_size;
	uint8_t *report;
};

struct DecryptDataParams
{
	uint8_t* (*allocate_callback)(size_t);
	size_t encrypted_size;
	uint8_t* encrypted_data;
	size_t tag_size;
	uint8_t* tag;
	size_t decrypted_size;
	uint8_t *decrypted_data;
};

struct AES256KeyBlob
{
	BCRYPT_KEY_DATA_BLOB_HEADER header;
	uint8_t key[32];
};

uint8_t *AllocateCallback(size_t size)
{
	return new uint8_t[size];
}

char hexchars[] = "0123456789abcdef";
void DumpBytes(_In_ uint8_t* buffer, size_t allocation_size) {
	for (size_t line = 0; line * 16 < allocation_size; line++) {
		uint8_t count = 0;
		while (count < 16) {
			std::cout << hexchars[((buffer[line * 16 + count]) & 0xf0) >> 4] << hexchars[(buffer[line * 16 + count]) & 0xf] << " ";
			count++;
			if (line * 16 + count == allocation_size) {
				break;
			}
		}

		for (size_t i = 0; i < 16 - count; i++) {
			std::cout << "   ";
		}

		for (size_t i = 0; i < count; i++) {
			if (buffer[line * 16 + i] >= 'A' && buffer[line * 16 + i] <= 'z') {
				std::cout << buffer[line * 16 + i];
			}
			else {
				std::cout << '.';
			}
		}

		std::cout << std::endl;
	}

}

int wmain(int argc, wchar_t **argv)
{
	if (argc != 3)
	{
		std::cerr << "Usage: EnclaveLoader.exe <enclave DLL path> <message>" << std::endl;
		return -1;
	}

	std::wstring enclave_name = argv[1];
	std::wstring message = argv[2];

	ENCLAVE_CREATE_INFO_VBS info{};

#ifdef _DEBUG
	info.Flags = ENCLAVE_VBS_FLAG_DEBUG;
#endif

	CopyMemory(&info.OwnerID, OwnerId, IMAGE_ENCLAVE_LONG_ID_LENGTH);

	LPVOID enclave_base = CreateEnclave(
		GetCurrentProcess(),
		nullptr,
		0x10000000,
		0,
		ENCLAVE_TYPE_VBS,
		&info,
		sizeof(ENCLAVE_CREATE_INFO_VBS),
		nullptr);

	if (enclave_base == nullptr)
	{
		std::cerr << "CreateEnclave failed: " << GetLastError() << std::endl;
		return -1;
	}

	if (!LoadEnclaveImage(enclave_base, enclave_name.c_str()))
	{
		std::cerr << "LoadEnclaveImage failed: " << GetLastError() << std::endl;
		return -1;
	}

	ENCLAVE_INIT_INFO_VBS init_info{};
	init_info.Length = sizeof(init_info);
	init_info.ThreadCount = 16;

	if (!InitializeEnclave(GetCurrentProcess(), enclave_base, &init_info, sizeof(init_info), nullptr))
	{
		std::cerr << "InitializeEnclave failed: " << GetLastError() << std::endl;
		return -1;
	}

	std::cout << "Rust enclave created and initialized!" << std::endl;

	PENCLAVE_ROUTINE new_keypair_v1 = (PENCLAVE_ROUTINE)GetProcAddress((HMODULE)enclave_base, "new_keypair_v1");
	PENCLAVE_ROUTINE generate_report_v1 = (PENCLAVE_ROUTINE)GetProcAddress((HMODULE)enclave_base, "generate_report_v1");
	PENCLAVE_ROUTINE decrypt_data_v1 = (PENCLAVE_ROUTINE)GetProcAddress((HMODULE)enclave_base, "decrypt_data_v1");

	std::cout << "my_enclave_function is " << std::hex << new_keypair_v1 << std::endl;
	std::cout << "generate_report_v1 is " << std::hex << generate_report_v1 << std::endl;
	std::cout << "decrypt_data_v1 is " << std::hex << decrypt_data_v1 << std::endl;

	BCRYPT_KEY_HANDLE keypair = nullptr;

	NTSTATUS status = BCryptGenerateKeyPair(
		BCRYPT_ECDH_P256_ALG_HANDLE,
		&keypair,
		256,
		0
	);

	if (status != 0) {
		std::cerr << "BCryptGenerateKeyPair failed: " << std::hex << status << std::endl;
		return status;
	}

	status = BCryptFinalizeKeyPair(keypair, 0);

	if (status != 0) {
		std::cerr << "BCryptFinalizeKeyPair failed: " << std::hex << status << std::endl;
		return status;
	}

	uint32_t blob_size = 0;

	status = BCryptExportKey(
		keypair,
		nullptr,
		BCRYPT_ECCPUBLIC_BLOB,
		nullptr,
		0,
		(ULONG*)&blob_size,
		0
	);

	if (status != 0) {
		std::cerr << "BCryptExportKey failed: " << std::hex << status << std::endl;
		return status;
	}

	if (blob_size != sizeof(BCRYPT_ECCKEY_BLOB) + ENCLAVE_REPORT_DATA_LENGTH) {
		std::cerr << "Export blob size is " << std::dec << blob_size << " bytes, expected " << sizeof(BCRYPT_ECCKEY_BLOB) + ENCLAVE_REPORT_DATA_LENGTH << " bytes!" << std::endl;
		return -1;
	}

	uint8_t* my_public_key_blob = new uint8_t[blob_size];

	status = BCryptExportKey(
		keypair,
		nullptr,
		BCRYPT_ECCPUBLIC_BLOB,
		my_public_key_blob,
		blob_size,
		(ULONG*)&blob_size,
		0
	);

	if (status != 0) {
		std::cerr << "Second BCryptExportKey failed: " << std::hex << status << std::endl;
		return status;
	}

	std::cout << "Creating new enclave key and providing host public key..." << std::endl;

	NewKeypairParams new_keypair_params = NewKeypairParams{256, my_public_key_blob};
	LPVOID result = nullptr;

	if (!CallEnclave(new_keypair_v1, &new_keypair_params, TRUE, &result) || (HRESULT)result != S_OK)
	{
		std::cerr << "new_keypair_v1 failed: " << std::hex << (HRESULT)result << std::endl;
		return (HRESULT)result;
	}

	std::cout << "New keypair created!" << std::endl;

	GenerateReportParams generate_report_params = GenerateReportParams{AllocateCallback};

	if (!CallEnclave(generate_report_v1, &generate_report_params, TRUE, &result) || (HRESULT)result != S_OK)
	{
		std::cerr << "generate_report_v1 failed: " << std::hex << (HRESULT)result << std::endl;
		return (HRESULT)result;
	}

	std::cout << "Report generated! " << std::dec << generate_report_params.report_size << " bytes!" << std::endl;

	VBS_ENCLAVE_REPORT *report = (VBS_ENCLAVE_REPORT *)((VBS_ENCLAVE_REPORT_PKG_HEADER *)generate_report_params.report + 1);

	/* This is where you would validate the attestation report before using the public key! */

	std::cout << "Beep boop beep, validating attestation report... (for pretend)" << std::endl;

	Sleep(1000);

	std::cout << "Enclave is validated!" << std::endl;

	BCRYPT_ECCKEY_BLOB *public_key_blob = (BCRYPT_ECCKEY_BLOB *)new uint8_t[sizeof(BCRYPT_ECCKEY_BLOB) + ENCLAVE_REPORT_DATA_LENGTH];

	public_key_blob->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
	public_key_blob->cbKey = ENCLAVE_REPORT_DATA_LENGTH / 2;

	memcpy(public_key_blob + 1, report->EnclaveData, ENCLAVE_REPORT_DATA_LENGTH);

	BCRYPT_KEY_HANDLE public_key_handle = nullptr;

	status = BCryptImportKeyPair(
		BCRYPT_ECDH_P256_ALG_HANDLE,
		nullptr,
		BCRYPT_ECCPUBLIC_BLOB,
		&public_key_handle,
		(PBYTE)public_key_blob,
		sizeof(BCRYPT_ECCKEY_BLOB) + ENCLAVE_REPORT_DATA_LENGTH,
		0
	);

	if (status != 0)
	{
		std::cerr << "BCryptImportKeyPair failed: " << std::hex << status << std::endl;
		return status;
	}

	std::cout << "Public key imported successfully!" << std::endl;

	BCRYPT_KEY_HANDLE agreed_secret = nullptr;

	status = BCryptSecretAgreement(keypair, public_key_handle, &agreed_secret, 0);

	if (status != 0) {
		std::cerr << "BCryptSecretAgreement failed: " << std::hex << status << std::endl;
		return status;
	}

	BCryptBuffer buffer = {
		sizeof(BCRYPT_SHA256_ALGORITHM),
		KDF_HASH_ALGORITHM,
		(PVOID)BCRYPT_SHA256_ALGORITHM
	};

	BCryptBufferDesc parameter_list = {
		BCRYPTBUFFER_VERSION,
		1,
		&buffer
	};

	AES256KeyBlob derived_key_blob = {
		{
			BCRYPT_KEY_DATA_BLOB_MAGIC,
			BCRYPT_KEY_DATA_BLOB_VERSION1,
			32
		},
		{}
	};
	uint32_t bytes_needed = 0;

	status = BCryptDeriveKey(agreed_secret, BCRYPT_KDF_HASH, &parameter_list, derived_key_blob.key, sizeof(derived_key_blob.key), (ULONG*)&bytes_needed, 0);

	if (status != 0) {
		std::cerr << "BCryptDeriveKey failed: " << std::hex << status << std::endl;
		return status;
	}

	BCRYPT_KEY_HANDLE ephemeral_key = nullptr;

	status = BCryptImportKey(BCRYPT_AES_GCM_ALG_HANDLE, nullptr, BCRYPT_KEY_DATA_BLOB, &ephemeral_key, nullptr, 0, (uint8_t*)& derived_key_blob, sizeof(derived_key_blob), 0);

	if (status != 0) {
		std::cerr << "BCryptImportKey failed: " << std::hex << status << std::endl;
		return status;
	}

	std::cout << "Successfully derived shared ephemeral key!" << std::endl;

	std::cout << "Encrypting the message:" << std::endl;
	DumpBytes((uint8_t*)message.c_str(), message.size() * sizeof(wchar_t));
	std::cout << std::endl;

	uint8_t iv[12] = {};
	uint8_t tag[16] = {};

	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO mode_info{};
	BCRYPT_INIT_AUTH_MODE_INFO(mode_info);

	mode_info.pbNonce = iv;
	mode_info.cbNonce = sizeof(iv);
	mode_info.pbTag = tag;
	mode_info.cbTag = sizeof(tag);

	status = BCryptEncrypt(
		ephemeral_key,
		(PUCHAR)message.c_str(),
		message.size() * sizeof(WCHAR),
		&mode_info,
		nullptr,
		0,
		nullptr,
		0,
		(ULONG*)&bytes_needed,
		0
	);

	if (status != 0) {
		std::cerr << "BCryptEncrypt failed to get size: " << std::hex << status << std::endl;
		return status;
	}

	uint8_t *ciphertext = new uint8_t[bytes_needed];

	status = BCryptEncrypt(
		ephemeral_key,
		(PUCHAR)message.c_str(),
		message.size() * sizeof(WCHAR),
		&mode_info,
		nullptr,
		0,
		ciphertext,
		bytes_needed,
		(ULONG*)&bytes_needed,
		0
	);

	if (status != 0) {
		std::cerr << "BCryptEncrypt failed to encrypt: " << std::hex << status << std::endl;
		return status;
	}
	
	std::cout << "Message successfully encrypted! Sending to enclave to decrypt..." << std::endl;

	DecryptDataParams decrypt_data_params = { AllocateCallback, bytes_needed, ciphertext, mode_info.cbTag, mode_info.pbTag };

	if (!CallEnclave(decrypt_data_v1, &decrypt_data_params, TRUE, &result) || (HRESULT)result != S_OK)
	{
		std::cerr << "decrypt_data_v1 failed: " << std::hex << (HRESULT)result << std::endl;
		return (HRESULT)result;
	}

	std::cout << "Data decrypted! Message is:" << std::endl;
	DumpBytes(decrypt_data_params.decrypted_data, decrypt_data_params.decrypted_size);

	TerminateEnclave(enclave_base, TRUE);

	DeleteEnclave(enclave_base);

	return 0;
}