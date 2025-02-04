#include <winenclave.h>
#include <cstdint>
#include <iostream>
#include <string>

const uint8_t OwnerId[IMAGE_ENCLAVE_LONG_ID_LENGTH] = { 0x10, 0x20, 0x30, 0x40, 0x41, 0x31, 0x21, 0x11 };

template<typename T>
struct VTL0Array {
	_In_ T* arr;
	_In_ size_t count;
};

struct MyEnclaveParams {
	_In_ uint32_t a;
	_In_ uint32_t b;
	_In_ uint32_t* c;
	_In_ VTL0Array<uint32_t> d;
	_Out_ uint32_t* e;
};

int wmain(int argc, wchar_t** argv) {
	if (argc != 2) {
		return -1;
	}

	std::wstring enclave_name = argv[1];

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
		nullptr
	);

	if (enclave_base == nullptr) {
		std::cerr << "CreateEnclave failed: " << GetLastError() << std::endl;
		return -1;
	}

	if (!LoadEnclaveImage(enclave_base, enclave_name.c_str())) {
		std::cerr << "LoadEnclaveImage failed: " << GetLastError() << std::endl;
		return -1;
	}

	ENCLAVE_INIT_INFO_VBS init_info{};
	init_info.Length = sizeof(init_info);
	init_info.ThreadCount = 16;

	if (!InitializeEnclave(GetCurrentProcess(), enclave_base, &init_info, sizeof(init_info), nullptr)) {
		std::cerr << "InitializeEnclave failed: " << GetLastError() << std::endl;
		return -1;
	}

	std::cout << "Rust enclave created and initialized!" << std::endl;

	PENCLAVE_ROUTINE my_enclave_function = (PENCLAVE_ROUTINE)GetProcAddress((HMODULE)enclave_base, "my_enclave_function");

	std::cout << "my_enclave_function is " << std::hex << my_enclave_function << std::endl;

	MyEnclaveParams param;

	param.a = 1;
	param.b = 2;
	uint32_t c = 3;
	param.c = &c;
	uint32_t d[] = {3, 4, 5};
	param.d = { d, _countof(d) };
	uint32_t e = 0;
	param.e = &e;

	LPVOID output = nullptr;

	std::cout << "a is " << std::dec << param.a << std::endl;
	std::cout << "b is " << std::dec << param.b << std::endl;
	std::cout << "c is " << std::dec << c << std::endl;
	std::cout << "d is " << std::dec;
	for (auto i : d) {
		std::cout << i << " ";
	}
	std::cout << std::endl;
	std::cout << "e is " << std::dec << e << std::endl;

	if (!CallEnclave(my_enclave_function, &param, TRUE, &output)) {
		std::cerr << "CallEnclave failed: " << std::dec << GetLastError() << std::endl;
		return -1;
	}

	// This should output S_OK if a + b == c, otherwise it will output E_INVALID_STATE
	std::cout << "my_enclave_function result: " << std::hex << output << std::endl;

	std::cout << "a is " << std::dec << param.a << std::endl;
	std::cout << "b is " << std::dec << param.b << std::endl;
	std::cout << "c is " << std::dec << c << std::endl;
	std::cout << "d is " << std::dec;
	for (auto i : d) {
		std::cout << i << " ";
	}
	std::cout << std::endl;
	std::cout << "e is " << std::dec << e << std::endl;

	TerminateEnclave(enclave_base, TRUE);

	DeleteEnclave(enclave_base);

	return 0;
}