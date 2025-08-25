#pragma once
#include "Thirdparty.hpp"
#include "Strings.hpp"
#include <minwindef.h>
#include <ntdef.h>

typedef enum _request_codes
{
	base_request = 0x119,
	read_virtual_request = 0x129,
	write_virtual_request = 0x139,
	allocate_request = 0x149,
	free_request = 0x159,
	protect_request = 0x169,
	loaded_request = 0x179,
	success_request = 0x189,
	query_virtual_memory_request = 0x199,
	unique_request = 0xDEED,
	PageGuardCopyMem = 0x1834,
	GetGuardedRegion = 0x1374,
	set_miscflag = 0420,
	EnableApc = 0x979,
	WriteDll = 0x866,
	Extend_Shit = 0x992,
	MODULE = 0x643,
	peb_request = 0x97,
	protect_sprite_request = 0x545,

} request_codes, * prequest_codes;

//Controlling Data Sent Between Driver and Usermode.
typedef struct _request_query_virtual_memory {
	DWORD process_id;
	PVOID address;
	PVOID out_address;
} request_query_virtual_memory, * prequest_query_virtual_memory;

typedef struct _request_extend {
	DWORD ProcessId;
	WCHAR Module[0xFF];
	DWORD Size;
} request_extend, * prequest_extend;

typedef struct _request_protect_sprite_content {
	uint32_t value;
	uint64_t window_handle;
}request_protect_sprite_content, * prequest_protect_sprite_content;

typedef struct _request_loaded {
	INT status;
} request_loaded, * prequest_loaded;

typedef struct _requst_Apc_Enabled {
	INT status;
} requst_Apc_Enabled, * prequst_Apc_Enabled;

typedef struct _request_misc {
	INT status;
} request_misc, * prequest_misc;

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

typedef struct _request_write_physical {
	DWORD process_id;
	uintptr_t address;
	void* buffer;
	size_t size;
} request_write_phys, * prequest_write_phys;

typedef struct _request_read_physical {
	DWORD process_id;
	uintptr_t address;
	void* buffer;
	size_t size;
} request_read_phys, * prequest_read_phys;

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

typedef struct _request_peb {
	DWORD process_id;
	uintptr_t peb;
	WCHAR name[260];
} request_peb, * prequest_peb;

typedef struct _request_free {
	DWORD process_id;
	PVOID address;
} request_free, * prequest_free;

typedef struct _request_data {
	DWORD unique;
	request_codes code;
	PVOID data;
} request_data, * prequest_data;

typedef struct _request_guarded {
	ULONGLONG GuardedPtr;
}request_guarded, * prequest_guarded;

typedef struct _request_base {
	DWORD Process;
	uintptr_t handle;
	WCHAR Name[260];
} request_base, * prequest_base;

namespace kernel_KPROCESS {

	// !_KPROCESS.UserDirectoryTableBase
	inline unsigned long long UserDirectoryTableBase = 0;
}

namespace Memory {
	auto SwapProcess(uintptr_t new_process) -> uintptr_t
	{
		uintptr_t current_thread = (uintptr_t)KeGetCurrentThread();

		uintptr_t apc_state = *(uintptr_t*)(current_thread + 0x98);
		uintptr_t old_process = *(uintptr_t*)(apc_state + 0x20);
		*(uintptr_t*)(apc_state + 0x20) = new_process;

		uintptr_t dir_table_base = *(uintptr_t*)(new_process + 0x28);
		__writecr3(dir_table_base);

		return old_process;
	}

	auto IsValidAddr(ULONG64 ptr) -> BOOLEAN
	{
		ULONG64 min = 0x0001000;
		ULONG64 max = 0x7FFFFFFEFFFF;
		BOOLEAN result = (ptr > min && ptr < max);
		return result;
	}
	auto IsValidProcess(HANDLE Process) -> bool {
		if (!Process)
			return false;

		PEPROCESS Proc;
		if (!NT_SUCCESS(PsLookupProcessByProcessId(Process, &Proc)))
			return false;

		return true;
	}
	auto SafeCopy(PVOID Destination, PVOID Source, SIZE_T Size) -> bool {
		SIZE_T returnSize = 0;
		if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), Source, PsGetCurrentProcess(), Destination, Size, KernelMode, &returnSize)) && returnSize == Size) {
			return TRUE;
		}

		return FALSE;
	}

	auto GetSysInfo(SYSTEM_INFORMATION_CLASS information_class)-> PVOID {
		ULONG size = 32;
		char buffer[32];
		ZwQuerySystemInformation(information_class, buffer, size, &size);
		//PVOID info = ExAllocatePoolZero(NonPagedPool, size, 7265746172);
		PVOID info = ExAllocatePool(NonPagedPool, size);
		if (!info) return nullptr;
		if (ZwQuerySystemInformation(information_class, info, size, &size) != STATUS_SUCCESS)
		{
			ExFreePool(info);
			return nullptr;
		}
		return info;
	}
	auto GetKernelModule(const char* Name) -> uintptr_t {
		const PRTL_PROCESS_MODULES Info = (PRTL_PROCESS_MODULES)GetSysInfo(SystemModuleInformation);
		if (!Info) 
			return 0;
		for (size_t i = 0; i < Info->NumberOfModules; ++i)
		{
			const auto& module = Info->Modules[i];
			if (strcmp(ToLower((char*)module.FullPathName + module.OffsetToFileName), Name) == 0)
			{
				const PVOID address = module.ImageBase;
				ExFreePool(Info);
				return (uintptr_t)address;
			}
		}
		ExFreePool(Info);
		return 0;
	}

	auto PatternScan(uintptr_t Base, size_t Range, const char* Pattern, const char* Mask) -> uintptr_t {
		const auto check_mask = [](const char* Base, const char* pattern, const char* mask) -> bool
			{
				for (; *mask; ++Base, ++pattern, ++mask)
				{
					if (*mask == 'x' && *Base != *pattern) return false;
				}
				return true;
			};
		Range = Range - strlen(Mask);
		for (size_t i = 0; i < Range; ++i)
		{
			if (check_mask((const char*)Base + i, Pattern, Mask)) return Base + i;
		}
		return 0;
	}
	auto PatternScan(uintptr_t Base, const char* pattern, const char* mask) -> uintptr_t {
		const PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
		const PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
		for (size_t i = 0; i < headers->FileHeader.NumberOfSections; i++)
		{
			const PIMAGE_SECTION_HEADER section = &sections[i];
			if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				const uintptr_t match = PatternScan(Base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
				if (match) return match;
			}
		}
		return 0;
	}

	auto GetModulePEB(DWORD Process, LPCWSTR ModName) -> uintptr_t {
		PEPROCESS TargetProcess;
		uintptr_t Base = 0;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)Process, &TargetProcess)))
			return 0;

		uintptr_t Proc = SwapProcess((uintptr_t)TargetProcess);
		PPEB peb = PsGetProcessPeb(TargetProcess);
		if (!peb)
			goto end;

		Base = (uintptr_t)peb;
		goto end;
	end:
		SwapProcess((uintptr_t)Proc);
		ObDereferenceObject(TargetProcess);
		return Base;
	}
	auto GetModuleHandle(DWORD Process, LPCWSTR ModName) -> uintptr_t {
		PEPROCESS TargetProcess;
		uintptr_t Base = 0;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)Process, &TargetProcess)))
			return 0;

		uintptr_t Proc = SwapProcess((uintptr_t)TargetProcess);

		PPEB peb = PsGetProcessPeb(TargetProcess);
		if (!peb)
			goto end;

		if (!peb->Ldr || !peb->Ldr->Initialized)
			goto end;

		UNICODE_STRING UModuleName;
		RtlInitUnicodeString(&UModuleName, ModName);
		for (PLIST_ENTRY list = peb->Ldr->InLoadOrderModuleList.Flink;
			list != &peb->Ldr->InLoadOrderModuleList;
			list = list->Flink) {
			PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (RtlCompareUnicodeString(&entry->BaseDllName, &UModuleName, TRUE) == 0) {
				Base = (uintptr_t)entry->DllBase;
				goto end;
			}
		}

	end:
		SwapProcess((uintptr_t)Proc);
		ObDereferenceObject(TargetProcess);
		return Base;
	}

	NTSTATUS read_phys_addr(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
	{
		if (!TargetAddress || !lpBuffer || Size <= 0)
			return STATUS_UNSUCCESSFUL;

		MM_COPY_ADDRESS AddrToRead = { 0 };
		AddrToRead.PhysicalAddress.QuadPart = (LONGLONG)TargetAddress;
		return MmCopyMemory(lpBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
	}
	ULONG_PTR get_process_cr3(PEPROCESS pProcess)
	{
		if (!pProcess)
			return 0;

		PUCHAR process = (PUCHAR)pProcess;
		ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28);
		if (process_dirbase == 0)
		{
			ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + kernel_KPROCESS::UserDirectoryTableBase);
			return process_userdirbase;
		}
		return process_dirbase;
	}

#define PAGE_OFFSET_SIZE 12
	static const UINT64 PMASK = (~0xfull << 8) & 0xfffffffffull;

	UINT64 translate_linear_address(UINT64 directoryTableBase, UINT64 virtualAddress)
	{
		if (!directoryTableBase || !virtualAddress)
			return 0;
		directoryTableBase &= ~0xf;

		UINT64 pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
		UINT64 pte = ((virtualAddress >> 12) & (0x1ffll));
		UINT64 pt = ((virtualAddress >> 21) & (0x1ffll));
		UINT64 pd = ((virtualAddress >> 30) & (0x1ffll));
		UINT64 pdp = ((virtualAddress >> 39) & (0x1ffll));

		SIZE_T readsize = 0;
		UINT64 pdpe = 0;
		read_phys_addr((PVOID)(directoryTableBase + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
		if (~pdpe & 1)
			return 0;

		UINT64 pde = 0;
		read_phys_addr((PVOID)((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde), &readsize);
		if (~pde & 1)
			return 0;

		/* 1GB large page, use pde's 12-34 bits */
		if (pde & 0x80)
			return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

		UINT64 pteAddr = 0;
		read_phys_addr((PVOID)((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr), &readsize);
		if (~pteAddr & 1)
			return 0;

		/* 2MB large page */
		if (pteAddr & 0x80)
			return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

		virtualAddress = 0;
		read_phys_addr((PVOID)((pteAddr & PMASK) + 8 * pte), &virtualAddress, sizeof(virtualAddress), &readsize);
		virtualAddress &= PMASK;

		if (!virtualAddress)
			return 0;

		return virtualAddress + pageOffset;
	}

	NTSTATUS write_phys_addr(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten)
	{
		if (!TargetAddress || !lpBuffer || Size <= 0)
			return STATUS_UNSUCCESSFUL;

		PHYSICAL_ADDRESS AddrToWrite = { 0 };
		AddrToWrite.QuadPart = (LONGLONG)TargetAddress;

		PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, Size, PAGE_READWRITE);

		if (!pmapped_mem)
			return STATUS_UNSUCCESSFUL;

		memcpy(pmapped_mem, lpBuffer, Size);

		if (BytesWritten)
			*BytesWritten = Size;

		MmUnmapIoSpace(pmapped_mem, Size);
		return STATUS_SUCCESS;
	}
	NTSTATUS write_phys_memory(HANDLE pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* written = nullptr)
	{
		PEPROCESS pProcess = NULL;
		if (!pid || !Address || !AllocatedBuffer || size <= 0) return STATUS_UNSUCCESSFUL;

		NTSTATUS NtRet = PsLookupProcessByProcessId(pid, &pProcess);
		if (NtRet != STATUS_SUCCESS) return NtRet;

		ULONG_PTR process_dirbase = get_process_cr3(pProcess);
		ObfDereferenceObject(pProcess);

		SIZE_T CurOffset = 0;
		SIZE_T TotalSize = size;
		while (TotalSize)
		{
			UINT64 CurPhysAddr = translate_linear_address(process_dirbase, (ULONG64)Address + CurOffset);
			if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

			ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
			SIZE_T BytesWritten = 0;
			NtRet = write_phys_addr((PVOID)CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), WriteSize, &BytesWritten);
			TotalSize -= BytesWritten;
			CurOffset += BytesWritten;
			if (NtRet != STATUS_SUCCESS) break;
			if (BytesWritten == 0) break;
		}

		if (written != nullptr)
			*written = CurOffset;
		return NtRet;
	}

	NTSTATUS read_phys_memory(HANDLE pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* read = nullptr)
	{
		PEPROCESS pProcess = NULL;
		if (!pid || !Address || !AllocatedBuffer || size <= 0) return STATUS_UNSUCCESSFUL;

		NTSTATUS NtRet = PsLookupProcessByProcessId(pid, &pProcess);
		if (NtRet != STATUS_SUCCESS) return NtRet;

		ULONG_PTR process_dirbase = get_process_cr3(pProcess);
		ObfDereferenceObject(pProcess);

		SIZE_T CurOffset = 0;
		SIZE_T TotalSize = size;
		while (TotalSize)
		{
			UINT64 CurPhysAddr = translate_linear_address(process_dirbase, (ULONG64)Address + CurOffset);
			if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

			ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
			SIZE_T BytesRead = 0;
			NtRet = read_phys_addr((PVOID)CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), ReadSize, &BytesRead);
			TotalSize -= BytesRead;
			CurOffset += BytesRead;
			if (NtRet != STATUS_SUCCESS) break;
			if (BytesRead == 0) break;
		}

		if (read != nullptr)
			*read = CurOffset;

		return NtRet;
	}
	/*auto GetBaseAddress(_request_base Data) -> PVOID {
		if (!Data->Process)
			return 0;
		PEPROCESS Proc = 0;
		PsLookupProcessByProcessId((HANDLE)Data->Process, &Proc);
		if (!Proc)
			return 0;

		PVOID ImageBase = PsGetProcessSectionBaseAddress(Proc);
		if (!ImageBase)
			return 0;

		ObDereferenceObject(Proc);
		return ImageBase;

	}*/
}
