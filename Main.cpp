#include "Memory.hpp"
#include "Core.hpp"
bool Once = true;
typedef unsigned __int64 QWORD;
__int64(__fastcall* original_function)(void* a1) = nullptr;

__int64 __fastcall hooked_function(void* a1) {
	if (!a1 || ExGetPreviousMode() != UserMode || reinterpret_cast<request_data*>(a1)->unique != unique_request) {
		return original_function(a1);
	}

	auto Request = reinterpret_cast<request_data*>(a1);

	//entering a guarded region to avoid stackwalk
	KeEnterGuardedRegion();

	switch (Request->code) {
	case base_request: {
		request_base data{ 0 };

		if (!Memory::SafeCopy(&data, Request->data, sizeof(request_base))) {
			KeLeaveGuardedRegion();
			return 0;
		}

		if (!data.Name || !data.Process) {
			KeLeaveGuardedRegion();
			return 0;
		}

		uintptr_t base = Memory::GetModuleHandle(data.Process, data.Name);

		if (!base) {
			KeLeaveGuardedRegion();
			return 0;
		}

		reinterpret_cast<request_base*>(Request->data)->handle = base;
		KeLeaveGuardedRegion();
		return success_request;
	}
	case write_virtual_request: {
		request_write data{ 0 };

		if (!Memory::SafeCopy(&data, Request->data, sizeof(request_write))) {

			KeLeaveGuardedRegion();
			return 0;
		}

		if (!data.address || !data.process_id || !data.buffer || !data.size) {

			KeLeaveGuardedRegion();
			return 0;
		}

		PEPROCESS process;
		if (PsLookupProcessByProcessId((HANDLE)data.process_id, &process) == STATUS_SUCCESS)
		{
			size_t bytes = 0;
			if (Memory::IsValidAddr(data.address) && Memory::IsValidAddr((ULONG64)data.buffer))
			{
				if (MmCopyVirtualMemory(IoGetCurrentProcess(), (void*)reinterpret_cast<request_write*>(Request->data)->buffer, process, (void*)data.address, data.size, KernelMode, &bytes) != STATUS_SUCCESS || bytes != data.size) {
					ObDereferenceObject(process);
					KeLeaveGuardedRegion();
					return 0;
				}
			}
			ObDereferenceObject(process);
		}
		else
		{
			KeLeaveGuardedRegion();
			return 0;
		}
		KeLeaveGuardedRegion();
		return success_request;
	}
	case query_virtual_memory_request: {
		request_query_virtual_memory data{ 0 };

		if (!Memory::SafeCopy(&data, Request->data, sizeof(request_query_virtual_memory))) {
			KeLeaveGuardedRegion();
			return 0;
		}

		core::query_virtual_memory(&data);

		KeLeaveGuardedRegion();
		return success_request;
	}
	case read_virtual_request: {
		request_read data{ 0 };

		if (!Memory::SafeCopy(&data, Request->data, sizeof(request_read))) {
			KeLeaveGuardedRegion();
			return 0;
		}

		if (!data.address || !data.process_id || !data.buffer || !data.size) {
			KeLeaveGuardedRegion();
			return 0;
		}

		PEPROCESS process;
		if (PsLookupProcessByProcessId((HANDLE)data.process_id, &process) == STATUS_SUCCESS)
		{
			size_t bytes = 0;
			if (Memory::IsValidAddr(data.address) && Memory::IsValidAddr((ULONG64)data.buffer))
			{
				if (MmCopyVirtualMemory(process, (void*)data.address, IoGetCurrentProcess(), reinterpret_cast<request_read*>(Request->data)->buffer, data.size, KernelMode, &bytes) != STATUS_SUCCESS || bytes != data.size) {
					ObDereferenceObject(process);
					KeLeaveGuardedRegion();
					return 0;
				}
			}
			ObDereferenceObject(process);
		}
		else
		{
			KeLeaveGuardedRegion();
			return 0;
		}
		KeLeaveGuardedRegion();
		return success_request;
	}
	case allocate_request: {
		request_allocate data{ 0 };

		if (!Memory::SafeCopy(&data, Request->data, sizeof(request_allocate))) {
			KeLeaveGuardedRegion();
			return 0;

		}

		core::allocate(&data);
		KeLeaveGuardedRegion();
		return success_request;
	}
	case protect_request: {
		request_protect data{ 0 };

		if (!Memory::SafeCopy(&data, Request->data, sizeof(request_allocate))) {
			KeLeaveGuardedRegion();
			return 0;

		}

		core::protect(&data);
		KeLeaveGuardedRegion();
		return success_request;
	}
	case free_request: {
		request_free data{ 0 };

		if (!Memory::SafeCopy(&data, Request->data, sizeof(request_free))) {
			KeLeaveGuardedRegion();
			return 0;
		}

		core::free(&data);
		KeLeaveGuardedRegion();
		return success_request;
	}
	case EnableApc: {
		requst_Apc_Enabled data{ 0 };


		if (!Memory::SafeCopy(&data, Request->data, sizeof(requst_Apc_Enabled))) {
			KeLeaveGuardedRegion();
			return 0;

		}

		KeLeaveGuardedRegion();
		return success_request;
	}
	/*
	case peb_request: {
		request_peb data{ 0 };

		if (!Memory::SafeCopy(&data, Request->data, sizeof(request_peb))) {
			KeLeaveGuardedRegion();
			return 0;
		}

		if (!data.name || !data.process_id) {
			KeLeaveGuardedRegion();
			return 0;
		}

		uintptr_t peb = Memory::GetModulePEB(data.process_id, data.name);

		if (!peb) {
			KeLeaveGuardedRegion();
			return 0;
		}

		reinterpret_cast<request_peb*>(Request->data)->peb = peb;
		KeLeaveGuardedRegion();
		return success_request;
	}*/
	case loaded_request: {
		request_loaded data{ 0 };

		if (!Memory::SafeCopy(&data, Request->data, sizeof(request_loaded))) {
			KeLeaveGuardedRegion();
			return 0;
		}

		if (!data.status) {
			KeLeaveGuardedRegion();
			return 0;
		}

		reinterpret_cast<request_loaded*>(Request->data)->status = 0x25;
		KeLeaveGuardedRegion();
		return success_request;
	}
	}

	KeLeaveGuardedRegion();
	return 0;
}

#define rva(addr, size)	((uintptr_t)(addr + *(DWORD*)(addr + ((size) - 4)) + size))
uintptr_t find_gadget(RTL_OSVERSIONINFOW os)
{
	uintptr_t base = Memory::GetKernelModule("win32k.sys");
	if (!base) return 0;

	uintptr_t function = 0;
	switch (os.dwBuildNumber) {
	case 22631: { //windows 11 23h2
		function = Memory::PatternScan(base, "\x48\x8B\x05\x31\x23\x06\x00\x48\x85\xC0\x74\x12\x4C\x8B\x54\x24", "xxxxxx?xxxxxxxxx"); // 48 8B 05 31 23 06 ? 48 85 C0 74 12 4C 8B 54 24
		break;
	}

	case 19045: { //windows 10 22h2
		function = Memory::PatternScan(base, "\x48\x8B\x05\x55\x9D\x05\x00\x48\x85\xC0\x74\x12\x4C\x8B\x54\x24\x60\x4C\x89\x54\x24", "xxxxxx?xxxxxxxxxxxxxx");
		break;
	}

	default: {
		function = 0; //not found
		break;
	}
	}

	if (!function)
		return 0;

	uintptr_t gadget = rva(function, 7);
	if (!gadget)
		return 0;

	return gadget;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	RTL_OSVERSIONINFOW os;
	RtlGetVersion(&os);
	uintptr_t gadget = find_gadget(os);

	*(void**)&original_function = _InterlockedExchangePointer((void**)gadget, hooked_function);

	return STATUS_SUCCESS;
}