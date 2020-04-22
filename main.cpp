#include <string>
#include <iostream>
#include <cstdio>
#include <Windows.h>
#include <psapi.h>


typedef struct _PEB_LDR_DATA {
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
	BYTE				Reserved1[2];		//0x0
	BYTE				BeingDebugged;		//0x2
	BYTE				Reserved2[1];		// 0x3
	PVOID				Reserved3[2];		// 0x5
	PPEB_LDR_DATA		Ldr;				// 0x0c
	void*				ProcessParameters;	//PRTL_USER_PROCESS_PARAMETERS	0x11
	BYTE				Reserved4[104];
	PVOID				Reserved5[52];
	void*				PostProcessInitRoutine; // PPS_POST_PROCESS_INIT_ROUTINE 
	BYTE				Reserved6[128];
	PVOID				Reserved7[1];
	ULONG				SessionId;
} PEB, *PPEB;

const char* GetProcessNameById(DWORD dwProcessId)
{
	char szProcessName[MAX_PATH] = TEXT("<unknown>");

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, dwProcessId);

	if (NULL != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
			&cbNeeded))
		{
			GetModuleBaseName(hProcess, hMod, szProcessName,
				sizeof(szProcessName) / sizeof(TCHAR));
		}
	}

	CloseHandle(hProcess);

	return szProcessName;
}

DWORD GetProcessIdByName(const char* szName)
{
	DWORD processes[1024];
	DWORD cbNeeded;
	
	BOOL bRet = EnumProcesses(processes, sizeof(processes), &cbNeeded);
	if (!bRet)
		return -1;

	for (size_t i = 0; i < 1024; i++)
	{
		if (!strcmp(GetProcessNameById(processes[i]), szName))
			return processes[i];
	}

	return -1;
}

PPEB GetPEB()
{
	__asm
	{
		mov eax, fs:[0x30]
	}
}

auto GetKernel32()
{
	return (GetPEB()->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink) + 0x10;
}

auto GetProcAddress_()
{
	return GetPEB()->Ldr->InMemoryOrderModuleList.Flink->Flink;
}

int main(int argc, char* argv[])
{
	//std::cout << GetKernel32();
	if (argc != 3)
	{
		std::cout << "PRIV8injector by: Couiz\n";
		std::cout << "Using: INJECTOR hack3.dll game.exe\n";
		return 1;
	}

	if (!strstr(argv[1], ".dll") && (!strstr(argv[2], ".exe") || !strstr(argv[2], ".bin")))
		return 2;

	std::string dllName = argv[1];
	std::string processName = argv[2];

	DWORD processId = GetProcessIdByName(processName.c_str());
	if (processId == -1)
		return 3;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (!hProcess)
		return 3;
	
	LPVOID allocAddr = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (allocAddr == nullptr)
		return 3;

	BOOL bRet = WriteProcessMemory(hProcess, allocAddr, dllName.c_str(), dllName.size(), NULL);
	if (!bRet)
		return 3;
	
	auto threadStart = GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA");
	std::cout << threadStart;
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)threadStart, allocAddr, 0, 0);

	std::cout << "__INJECTION SUCCESFULLY__\nhave fun :DD ~Couiz\n";
	MessageBox(0, "__INJECTION SUCCESFULLY__\nhave fun :DD ~Couiz", "Have Fun :D", 0);


	CloseHandle(hProcess);
	CloseHandle(hThread);

	return 0;
}