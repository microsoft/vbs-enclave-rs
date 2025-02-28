#include <winenclave.h>
#include <cstdint>
#include <iostream>
#include <string>
#include <memory>
#include <utility>
#include <wil/resource.h>

// These suppress some warnings for casting LPVOID to HRESULT
// and other truncation type issues when passing parameters and
// return values back from CallEnclave.
#pragma warning (disable : 4311)
#pragma warning (disable : 4302)
#pragma warning (disable : 4267)

void CleanupEnclave(void* enclave_base) {
	TerminateEnclave(enclave_base, TRUE);
	DeleteEnclave(enclave_base);
}

using Enclave = std::unique_ptr<void, decltype(&CleanupEnclave)>;

const uint8_t OwnerId[IMAGE_ENCLAVE_LONG_ID_LENGTH] = {0x10, 0x20, 0x30, 0x40, 0x41, 0x31, 0x21, 0x11};

struct NewKeypairParams
{
	uint32_t key_size;
	uint8_t *public_key;


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
	size_t iv_size;
	uint8_t* iv;
	size_t tag_size;
	uint8_t* tag;
	size_t decrypted_size;
	uint8_t *decrypted_data;
};

const uint32_t KeySize = 256;

struct AES256KeyBlob
{
	BCRYPT_KEY_DATA_BLOB_HEADER header;
	uint8_t key[32];
};

uint8_t *AllocateCallback(size_t size)
{
	auto allocation = std::make_unique<uint8_t[]>(size);
	return allocation.release();
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

void* StartEnclave(std::wstring enclave_name) {
	ENCLAVE_CREATE_INFO_VBS info{};

#ifdef _DEBUG
	info.Flags = ENCLAVE_VBS_FLAG_DEBUG;
#endif

	CopyMemory(&info.OwnerID, OwnerId, IMAGE_ENCLAVE_LONG_ID_LENGTH);

	void* enclave_base = CreateEnclave(
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
		return nullptr;
	}

	if (!LoadEnclaveImage(enclave_base, enclave_name.c_str()))
	{
		std::cerr << "LoadEnclaveImage failed: " << GetLastError() << std::endl;
		return nullptr;
	}

	ENCLAVE_INIT_INFO_VBS init_info{};
	init_info.Length = sizeof(init_info);
	init_info.ThreadCount = 16;

	if (!InitializeEnclave(GetCurrentProcess(), enclave_base, &init_info, sizeof(init_info), nullptr))
	{
		std::cerr << "InitializeEnclave failed: " << GetLastError() << std::endl;
		return nullptr;
	}

	return enclave_base;
}

wil::unique_bcrypt_key GenerateECDHKeypair() {
	wil::unique_bcrypt_key keypair = nullptr;

	NTSTATUS status = BCryptGenerateKeyPair(
		BCRYPT_ECDH_P256_ALG_HANDLE,
		&keypair,
		256,
		0
	);

	if (status != 0) {
		std::cerr << "BCryptGenerateKeyPair failed: " << std::hex << status << std::endl;
		return nullptr;
	}

	status = BCryptFinalizeKeyPair(keypair.get(), 0);

	if (status != 0) {
		std::cerr << "BCryptFinalizeKeyPair failed: " << std::hex << status << std::endl;
		return nullptr;
	}

	return keypair;
}

std::unique_ptr<uint8_t[]> ExportPublicKey(BCRYPT_KEY_HANDLE keypair) {
	uint32_t blob_size = 0;

	NTSTATUS status = BCryptExportKey(
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
		return nullptr;
	}

	if (blob_size != sizeof(BCRYPT_ECCKEY_BLOB) + ENCLAVE_REPORT_DATA_LENGTH) {
		std::cerr << "Export blob size is " << std::dec << blob_size << " bytes, expected " << sizeof(BCRYPT_ECCKEY_BLOB) + ENCLAVE_REPORT_DATA_LENGTH << " bytes!" << std::endl;
		return nullptr;
	}

	auto my_public_key_blob = std::make_unique<uint8_t[]>(blob_size);

	if (nullptr == my_public_key_blob) {
		std::cerr << "Failed to allocate " << std::dec << blob_size << " bytes for public key!" << std::endl;
		return nullptr;
	}

	status = BCryptExportKey(
		keypair,
		nullptr,
		BCRYPT_ECCPUBLIC_BLOB,
		my_public_key_blob.get(),
		blob_size,
		(ULONG*)&blob_size,
		0
	);

	if (status != 0) {
		std::cerr << "Second BCryptExportKey failed: " << std::hex << status << std::endl;
		return nullptr;
	}

	return my_public_key_blob;
}

bool CreateEnclaveKeypair(void* enclave_base, uint8_t* public_key_blob) {
	PENCLAVE_ROUTINE new_keypair = (PENCLAVE_ROUTINE)GetProcAddress((HMODULE)enclave_base, "new_keypair");

	if (nullptr == new_keypair) {
		std::cerr << "Failed to get new_keypair entry point! Error: " << std::hex << HRESULT_FROM_WIN32(GetLastError()) << std::endl;
		return false;
	}

	NewKeypairParams new_keypair_params = NewKeypairParams{ KeySize, public_key_blob };
	void* result = nullptr;

	if (!CallEnclave(new_keypair, &new_keypair_params, TRUE, &result) || (HRESULT)result != S_OK)
	{
		std::cerr << "new_keypair failed: " << std::hex << (HRESULT)result << std::endl;
		return false;
	}

	return true;
}

std::unique_ptr<uint8_t[]> GetAttestationReport(void* enclave_base) {
	PENCLAVE_ROUTINE generate_report = (PENCLAVE_ROUTINE)GetProcAddress((HMODULE)enclave_base, "generate_report");

	if (nullptr == generate_report) {
		std::cerr << "Failed to get generate_report entry point! Error: " << std::hex << HRESULT_FROM_WIN32(GetLastError()) << std::endl;
		return nullptr;
	}

	GenerateReportParams generate_report_params = GenerateReportParams{ AllocateCallback };
	void* result = nullptr;

	if (!CallEnclave(generate_report, &generate_report_params, TRUE, &result) || (HRESULT)result != S_OK)
	{
		std::cerr << "generate_report failed: " << std::hex << (HRESULT)result << std::endl;
		return nullptr;
	}

	std::cout << "Report generated! " << std::dec << generate_report_params.report_size << " bytes!" << std::endl;

	auto report_buffer = std::unique_ptr<uint8_t[]>(generate_report_params.report);
	return report_buffer;
}

wil::unique_bcrypt_key DeriveSharedKey(BCRYPT_KEY_HANDLE keypair, uint8_t* public_key_blob) {
	BCRYPT_KEY_HANDLE public_key_handle = nullptr;

	NTSTATUS status = BCryptImportKeyPair(
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
		return nullptr;
	}

	std::cout << "Public key imported successfully!" << std::endl;

	wil::unique_bcrypt_key agreed_secret = nullptr;

	status = BCryptSecretAgreement(keypair, public_key_handle, &agreed_secret, 0);

	if (status != 0) {
		std::cerr << "BCryptSecretAgreement failed: " << std::hex << status << std::endl;
		return nullptr;
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

	status = BCryptDeriveKey(agreed_secret.get(), BCRYPT_KDF_HASH, &parameter_list, derived_key_blob.key, sizeof(derived_key_blob.key), (ULONG*)&bytes_needed, 0);

	if (status != 0) {
		std::cerr << "BCryptDeriveKey failed: " << std::hex << status << std::endl;
		return nullptr;
	}

	wil::unique_bcrypt_key ephemeral_key = nullptr;

	status = BCryptImportKey(BCRYPT_AES_GCM_ALG_HANDLE, nullptr, BCRYPT_KEY_DATA_BLOB, &ephemeral_key, nullptr, 0, (uint8_t*)&derived_key_blob, sizeof(derived_key_blob), 0);

	if (status != 0) {
		std::cerr << "BCryptImportKey failed: " << std::hex << status << std::endl;
		return nullptr;
	}

	return ephemeral_key;
}

using BufferInfo = std::pair<uint8_t*, size_t>;
BufferInfo EncryptMessage(BCRYPT_HANDLE ephemeral_key, std::wstring message, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO& mode_info) {
	DumpBytes((uint8_t*)message.c_str(), message.size() * sizeof(wchar_t));
	std::cout << std::endl;

	uint32_t bytes_needed = 0;

	NTSTATUS status = BCryptEncrypt(
		ephemeral_key,
		(PUCHAR)message.c_str(),
		message.size() * sizeof(wchar_t),
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
		return std::make_pair(nullptr, 0);
	}

	auto ciphertext = new uint8_t[bytes_needed];

	if (ciphertext == nullptr) {
		std::cerr << "Failed to allocate buffer for ciphertext" << std::endl;
		return std::make_pair(nullptr, 0);
	}

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
		return std::make_pair(nullptr, 0);
	}

	return std::make_pair(ciphertext, bytes_needed);
}

std::wstring DecryptMessage(void* enclave_base, DecryptDataParams &decrypt_data_params) {
	PENCLAVE_ROUTINE decrypt_data = (PENCLAVE_ROUTINE)GetProcAddress((HMODULE)enclave_base, "decrypt_data");

	if (nullptr == decrypt_data) {
		std::cerr << "Could not get at least one of the enclave routines!" << std::endl;
		return nullptr;
	}

	void* result = nullptr;

	if (!CallEnclave(decrypt_data, &decrypt_data_params, TRUE, &result) || (HRESULT)result != S_OK)
	{
		std::cerr << "decrypt_data failed: " << std::hex << (HRESULT)result << std::endl;
		return nullptr;
	}

	std::wstring decrypted_data((const wchar_t*)decrypt_data_params.decrypted_data, decrypt_data_params.decrypted_size / sizeof(wchar_t));

	delete[] decrypt_data_params.decrypted_data;
	decrypt_data_params.decrypted_data = nullptr;

	return decrypted_data;
}

int wmain(int argc, wchar_t **argv)
{
	if (argc != 3)
	{
		std::cerr << "Usage: EnclaveLoader.exe <enclave DLL path> <message>" << std::endl;
		return -1;
	}

	std::wstring message = argv[2];

	Enclave enclave_base(StartEnclave(argv[1]), &CleanupEnclave);

	if (nullptr == enclave_base) {
		return -1;
	}

	std::cout << "Rust enclave created and initialized!" << std::endl;

	std::cout << "Creating host keypair..." << std::endl;

	auto keypair = GenerateECDHKeypair();

	if (!keypair.is_valid()) {
		return -1;
	}

	auto my_public_key_blob = ExportPublicKey(keypair.get());

	std::cout << "Creating new enclave key and providing host public key..." << std::endl;

	if (!CreateEnclaveKeypair(enclave_base.get(), my_public_key_blob.get())) {
		return -1;
	}

	std::cout << "New keypair created!" << std::endl;

	auto report_buffer = GetAttestationReport(enclave_base.get());

	VBS_ENCLAVE_REPORT *report = (VBS_ENCLAVE_REPORT *)((VBS_ENCLAVE_REPORT_PKG_HEADER *)report_buffer.get() + 1);

	/* This is where you would validate the attestation report before using the public key! */

	std::cout << "Beep boop beep, validating attestation report... (for pretend)" << std::endl;

	Sleep(1000);

	std::cout << "Enclave is validated!" << std::endl;

	auto public_key_blob = std::make_unique<uint8_t[]>(sizeof(BCRYPT_ECCKEY_BLOB) + ENCLAVE_REPORT_DATA_LENGTH);
	BCRYPT_ECCKEY_BLOB *public_key_blob_header = (BCRYPT_ECCKEY_BLOB *)public_key_blob.get();

	public_key_blob_header->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
	public_key_blob_header->cbKey = ENCLAVE_REPORT_DATA_LENGTH / 2;

	memcpy(public_key_blob_header + 1, report->EnclaveData, ENCLAVE_REPORT_DATA_LENGTH);

	std::cout << "Deriving shared key..." << std::endl;

	auto ephemeral_key = DeriveSharedKey(keypair.get(), public_key_blob.get());

	std::cout << "Successfully derived shared ephemeral key!" << std::endl;

	std::cout << "Encrypting the message:" << std::endl;
	
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO mode_info{};
	BCRYPT_INIT_AUTH_MODE_INFO(mode_info);

	uint8_t iv[12] = {};

	// Never use a static IV for AES-GCM unless you only ever use the key once!
	if (BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, iv, sizeof(iv), 0) != 0) {
		std::cerr << "BCryptGenRandom failed!" << std::endl;
		return -1;
	}

	mode_info.pbNonce = iv;
	mode_info.cbNonce = sizeof(iv);

	uint8_t tag[16] = {};
	mode_info.pbTag = tag;
	mode_info.cbTag = sizeof(tag);

	auto ciphertext_info = EncryptMessage(ephemeral_key.get(), message, mode_info);

	auto ciphertext = std::unique_ptr<uint8_t[]>(ciphertext_info.first);

	size_t bytes_needed = ciphertext_info.second;

	if (ciphertext == nullptr) {
		return -1;
	}
	
	DecryptDataParams decrypt_data_params = { 
		AllocateCallback,
		bytes_needed,
		ciphertext.get(),
		mode_info.cbNonce,
		mode_info.pbNonce,
		mode_info.cbTag,
		mode_info.pbTag
	};
	auto decrypted_data = DecryptMessage(enclave_base.get(), decrypt_data_params);

	std::cout << "Data decrypted! Message is:" << std::endl;
	DumpBytes((uint8_t*)decrypted_data.c_str(), decrypted_data.size() * sizeof(wchar_t));
	std::cout << std::endl;

	if (message.compare(decrypted_data) == 0) {
		std::cout << "The message round-tripped!" << std::endl;
	}
	else {
		std::cerr << "The message did not round-trip!" << std::endl;
		return -1;
	}

	return 0;
}