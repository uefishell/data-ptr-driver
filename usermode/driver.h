#define _CRT_SECURE_NO_WARNINGS
#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS 
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <codecvt>
#include <vector>

#define STR_BUFFER_SIZE 64
#define WSTR_BUFFER_SIZE 1024

class Driver
{
private:
	__int64(__fastcall* original_function)(void*) = nullptr;
	typedef enum _request_codes
	{
		base_request = 0x119,
		read_request = 0x129,
		write_request = 0x139,
		allocate_request = 0x149,
		free_request = 0x159,
		protect_request = 0x169,
		loaded_request = 0x179,
		success_request = 0x189,
		query_virtual_memory_request = 0x199,
		unique_request = 0xDEED,
		EnableApc = 0x979,
	} request_codes, * prequest_codes;
	typedef struct _requst_Apc_Enabled {

		INT status;
	} requst_Apc_Enabled, * prequst_Apc_Enabled;
	typedef struct _request_query_virtual_memory {
		DWORD process_id;
		PVOID address;
		PVOID out_address;
	} request_query_virtual_memory, * prequest_query_virtual_memory;
	typedef struct _request_loaded {
		INT status;
	} request_loaded, * prequest_loaded;
	typedef struct _request_write {
		DWORD process_id;
		uintptr_t address;
		void* buffer;
		size_t size;
	} request_write, * prequest_write;
	typedef struct _request_read {
		DWORD process_id;
		uintptr_t address;
		void* buffer;
		size_t size;
	} request_read, * prequest_read;
	typedef struct _request_allocate {
		DWORD process_id;
		PVOID out_address;
		DWORD size;
		DWORD protect;
	} request_allocate, * prequest_allocate;
	typedef struct _request_protect {
		DWORD process_id;
		PVOID address;
		DWORD size;
		PDWORD inoutprotect;
	} request_protect, * prequest_protect;
	typedef struct _request_base {
		DWORD process_id;
		uintptr_t handle;
		WCHAR name[260];
	} request_base, * prequest_base;
	typedef struct _request_free {
		DWORD process_id;
		PVOID address;
	} request_free, * prequest_free;
	typedef struct _request_data {
		DWORD unique;
		request_codes code;
		PVOID data;
	} request_data, * prequest_data;
public:
	bool loaded = false;
	DWORD process_id;
	inline auto initialize() -> bool
	{
		HMODULE user32 = LoadLibrary(("user32.dll"));
		HMODULE win32u = LoadLibrary(("win32u.dll"));

		if (!win32u and !user32) {
			return false;
		}

		*(void**)&original_function = GetProcAddress(win32u, ("NtGdiXFORMOBJ_bApplyXform"));

		if (!original_function) {
			return false;
		}
		return true;
	}

	inline auto send_cmd(void* data, request_codes code) -> bool
	{
		if (!data || !code) {
			return false;
		}

		request_data request{ 0 };

		request.unique = unique_request;
		request.data = data;
		request.code = code;

		const auto result = original_function(&request);
		if (result == NULL)
		{
			return false;
		}
		if (result != success_request) {
			return false;
		}

		return true;
	}

	DWORD get_process_id(LPCWSTR process_name)
	{
		HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		DWORD process_id = NULL;

		if (handle == INVALID_HANDLE_VALUE)
			return process_id;

		PROCESSENTRY32W entry = { 0 };
		entry.dwSize = sizeof(PROCESSENTRY32W);

		if (Process32FirstW(handle, &entry)) {
			if (!_wcsicmp(process_name, entry.szExeFile))
			{
				process_id = entry.th32ProcessID;
			}
			else while (Process32NextW(handle, &entry))
			{
				if (!_wcsicmp(process_name, entry.szExeFile))
				{
					process_id = entry.th32ProcessID;
				}
			}
		}
		CloseHandle(handle);
		return process_id;
	}

	inline auto readvm(uintptr_t address, void* buffer, size_t size) -> bool
	{
		request_read data{ 0 };

		data.process_id = process_id;
		data.address = address;
		data.buffer = buffer;
		data.size = size;

		return send_cmd(&data, read_request);
	}

	template <typename t>
	inline auto read(uintptr_t address) -> t
	{
		t response{ };
		readvm(address, &response, sizeof(t));
		return response;
	}
	template<typename T>
	T ReadChain(uintptr_t Va, std::vector<uint64_t> chain)
	{
		uint64_t current = Va;
		for (int i = 0; i < chain.size() - 1; i++)
		{
			current = read<uint64_t>(current + chain[i]);
		}
		return read<T>(current + chain[chain.size() - 1]);
	}

	std::string GetUnicodeString(uint64_t address, uint64_t string_length)
	{
		char16_t wcharTemp[64] = {};

		readvm(address, &wcharTemp, string_length);

		int utf8_length = WideCharToMultiByte(CP_UTF8, 0, reinterpret_cast<LPCWCH>(wcharTemp), -1, nullptr, 0, nullptr, nullptr);
		std::string u8_conv(utf8_length, 0);
		WideCharToMultiByte(CP_UTF8, 0, reinterpret_cast<LPCWCH>(wcharTemp), -1, &u8_conv[0], utf8_length, nullptr, nullptr);

		return u8_conv;
	}

	std::string ReadStr(uintptr_t address, int size = STR_BUFFER_SIZE) {
		std::unique_ptr<char[]> buffer(new char[size]);
		readvm(address, buffer.get(), size);

		if (!buffer.get())
			return "invalid";

		return std::string(buffer.get());
	}

	inline auto write(uintptr_t address, void* buffer, size_t size) -> bool
	{
		request_write data{ 0 };

		data.process_id = process_id;
		data.address = address;
		data.buffer = buffer;
		data.size = size;

		return send_cmd(&data, write_request);
	}

	template <typename t>
	inline auto write(uintptr_t address, t value) -> bool
	{
		return write(address, &value, sizeof(t));
	}

	inline auto allocate(DWORD size, DWORD protect) -> PVOID
	{
		PVOID out_address = NULL;

		request_allocate data{ 0 };

		data.process_id = process_id;
		data.out_address = &out_address;
		data.size = size;
		data.protect = protect;

		send_cmd(&data, allocate_request);

		return out_address;
	}

	inline auto query_virtual_memory(IN CONST PVOID address, OUT CONST PVOID out) -> bool
	{
		request_query_virtual_memory data{ 0 };

		data.process_id = process_id;
		data.address = address;
		data.out_address = out;

		return send_cmd(&data, query_virtual_memory_request);
	}

	inline auto protect(uintptr_t address, DWORD size, PDWORD inoutprotect) -> bool {
		request_protect data{ 0 };
		data.process_id = process_id;
		data.address = (PVOID)address;
		data.size = size;
		data.inoutprotect = inoutprotect;

		return send_cmd(&data, protect_request);
	}

	inline auto get_module_base(std::string module_name) -> uintptr_t
	{
		request_base data{ 0 };

		data.process_id = process_id;
		data.handle = 0;

		std::wstring wstr{ std::wstring(module_name.begin(), module_name.end()) };

		memset(data.name, 0, sizeof(WCHAR) * 260);
		wcscpy(data.name, wstr.c_str());

		send_cmd(&data, base_request);

		return data.handle;
	}

	inline auto free(PVOID address) -> bool
	{
		request_free data{ 0 };

		data.process_id = process_id;
		data.address = address;

		return send_cmd(&data, free_request);
	}

	inline auto is_driver_loaded() -> bool
	{
		request_loaded data{ 0 };

		data.status = 0x17;

		send_cmd(&data, loaded_request);

		return data.status == 0x25;
	}

	auto ValidPointer(uintptr_t pointer) -> bool
	{
		return (pointer && pointer > 0xFFFFFF && pointer < 0x7FFFFFFFFFFF);
	}
}driver;


