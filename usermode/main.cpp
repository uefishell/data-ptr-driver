#include "driver.h"

int main()
{
	driver.initialize();

	driver.process_id = driver.get_process_id(L"notepad.exe");
	DWORD base = driver.get_module_base("notepad.exe");
	printf("base: 0x%llx", base);

	DWORD test = driver.read<uint64_t>(base + 0x1);
	printf("\ntest: 0x%llx", test);

	system("pause>nul");
}