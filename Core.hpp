#include "Thirdparty.hpp"
#include "Memory.hpp"

namespace core {

	NTSTATUS query_virtual_memory(prequest_query_virtual_memory args) {
		PEPROCESS process = NULL;
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)args->process_id, &process);
		if (NT_SUCCESS(status))
		{
			MEMORY_BASIC_INFORMATION mbi;

			KeAttachProcess(process);
			ZwQueryVirtualMemory(NtCurrentProcess(), args->address, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
			KeDetachProcess();

			Memory::SafeCopy(args->out_address, &mbi, sizeof(mbi));

			ObDereferenceObject(process);
		}

		return status;
	}

	NTSTATUS allocate(prequest_allocate args) {
		PEPROCESS process = NULL;
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)args->process_id, &process);
		if (NT_SUCCESS(status))
		{
			PVOID address = NULL;
			SIZE_T size = args->size;

			KeAttachProcess(process);
			ZwAllocateVirtualMemory(NtCurrentProcess(), &address, 0, &size, MEM_COMMIT | MEM_RESERVE, args->protect);
			KeDetachProcess();

			Memory::SafeCopy(args->out_address, &address, sizeof(address));

			ObDereferenceObject(process);
		}

		return status;
	}

	NTSTATUS protect(prequest_protect args) {
		PEPROCESS process = NULL;
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)args->process_id, &process);
		if (NT_SUCCESS(status))
		{
			KAPC_STATE apc;
			ULONG old_protection;

			KeStackAttachProcess(process, &apc);
			status = ZwProtectVirtualMemory(ZwCurrentProcess(), &args->address, (PSIZE_T)args->size, (ULONG)args->inoutprotect, &old_protection);
			KeUnstackDetachProcess(&apc);
			args->inoutprotect = (PDWORD)old_protection;

			ObDereferenceObject(process);
		}

		return status;
	}

	NTSTATUS free(prequest_free args) {
		PEPROCESS process = NULL;
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)args->process_id, &process);
		if (NT_SUCCESS(status))
		{
			SIZE_T size = 0;

			KeAttachProcess(process);//Need to Fix this to not use kestach attach for eac
			ZwFreeVirtualMemory(NtCurrentProcess(), &args->address, &size, MEM_RELEASE);
			KeDetachProcess();

			ObDereferenceObject(process);
		}

		return status;
	}




}