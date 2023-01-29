DWORD UDPID;
uintptr_t baseaddy;

__int64(__fastcall* function_address)(void*) = nullptr;

enum Request {
	GETBASE = 0,
	READPROCESSMEMORY = 1,
	WRITEPROCESSMEMORY = 2,
	OPENHANDLE = 3,
};

struct ThermalUD {

	Request Request;
	DWORD processID;
	DWORD Reason;
	PVOID Outbase;
	uintptr_t Address;
	uintptr_t result;
	size_t size;
	const char* moduleName;
};

namespace DriverCommunication {

	typedef PVOID(*_FetchBaseAddy_t)(DWORD, const char*, __int64(__fastcall*)(void*));
	_FetchBaseAddy_t FetchBaseAddy = (_FetchBaseAddy_t)(void*)_BaseAddyRequest;

	typedef PVOID(*_PhysicalRead_t)(DWORD, uintptr_t, void*, uint32_t, __int64(__fastcall*)(void*));
	_PhysicalRead_t PhysicalRead = (_PhysicalRead_t)(void*)_PhysicalReadRequest;

	typedef PVOID(*_PhysicalWrite_t)(DWORD, uintptr_t, uint8_t*, uint32_t, __int64(__fastcall*)(void*));
	_PhysicalWrite_t PhysicalWrite = (_PhysicalWrite_t)(void*)_PhysicalWriteRequest;

	void LoadCommunicationShellCode(unsigned char* shellcode) {
		DWORD old_flag;
		VirtualProtect(shellcode, sizeof shellcode, PAGE_EXECUTE_READWRITE, &old_flag);
	}

	BOOL InitDrv() {

		for (unsigned int m = 0; m < sizeof(dll); ++m) { unsigned char c = dll[m]; c ^= 0x49; c = (c >> 0x6) | (c << 0x2); c += 0xf4; c ^= 0xa5; c -= m; c ^= 0xa9; c = -c; c = (c >> 0x2) | (c << 0x6); c = -c; c += 0x79; c = -c; c += m; c = (c >> 0x1) | (c << 0x7); c -= m; c = (c >> 0x7) | (c << 0x1); dll[m] = c; }

		for (unsigned int m = 0; m < sizeof(userInit); ++m) { unsigned char c = userInit[m]; c += m; c ^= m; c -= m; c ^= m; c = -c; c ^= 0x92; c += 0xb2; c ^= 0x6f; c += 0xf3; c ^= 0x98; c = (c >> 0x6) | (c << 0x2); c = ~c; c += 0xf0; c = -c; c = (c >> 0x6) | (c << 0x2); userInit[m] = c; }

		for (unsigned int m = 0; m < sizeof(function); ++m) { unsigned char c = function[m]; c -= 0x16; c ^= m; c += m; c = (c >> 0x7) | (c << 0x1); c ^= m; c = ~c; c += m; c ^= m; c -= 0xe0; c = -c; c += m; c ^= 0xfa; c = -c; c = (c >> 0x2) | (c << 0x6); c += m; function[m] = c; }

		LoadLibraryA((LPCSTR)dll);

		const auto win32k = LoadLibraryA((LPCSTR)userInit);

		if (!win32k)
			return false;

		*(void**)&function_address = GetProcAddress(win32k, (LPCSTR)function);

		if (function_address) {
			LoadCommunicationShellCode(_BaseAddyRequest);
			LoadCommunicationShellCode(_PhysicalReadRequest);
			LoadCommunicationShellCode(_PhysicalWriteRequest);
			return true;
		}
		else {
			return false;
		}

	}
}

template <typename T>
T read(const uintptr_t address)
{
	T buffer{ };
	DriverCommunication::PhysicalRead(UDPID, address, (uint8_t*)&buffer, sizeof(T), function_address);
	return buffer;
}


template <typename T>
void write(const uintptr_t address, T value)
{
	DriverCommunication::PhysicalWrite(UDPID, address, (uint8_t*)&value, sizeof(T), function_address);
}
