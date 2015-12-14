#include <Windows.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <stdio.h>

#define TARGET_EXE "TestEXE.exe"
#define DLL_FILE "InjectDll.dll"

int main(void)
{
	//get dll path
	TCHAR dllPath[256];
	GetModuleFileName(NULL, dllPath, sizeof(dllPath));
	int dllPathLen =(lstrlen(dllPath) + 1)*sizeof(TCHAR);

	_tcscpy_s(_tcsrchr(dllPath, _T('\\')) + 1, dllPathLen, _T(DLL_FILE));

	DWORD targetProcId = 0; //target process id

	//search target process
	HANDLE hSnapShot;
	if ((hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE){
		//CreateToolhelp32Snapshot Error
		MessageBox(NULL, _T("CreateToolhelp32Snapshot"), _T("Error"), MB_OK);
		return -1;
	}

	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL result = Process32First(hSnapShot, &pEntry);
	while (result){
		if (lstrcmp(_T(TARGET_EXE), pEntry.szExeFile) == 0){
			targetProcId = pEntry.th32ProcessID;
			break;
		}
		result = Process32Next(hSnapShot, &pEntry);
	}

	CloseHandle(hSnapShot);

	if (targetProcId == 0){
		MessageBox(NULL, _T("Process Not Found."), _T("Error"), MB_OK);
		return -1;
	}

	//open target process
	HANDLE hTargetProc;
	if ((hTargetProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcId)) == NULL){
		//OpenProcess Error
		MessageBox(NULL, _T("OpenProcess"), _T("Error"), MB_OK);
		return -1;
	}

	//VirtualAlloc
	PWSTR memAddr;
	if ((memAddr = (PWSTR)VirtualAllocEx(hTargetProc, NULL, dllPathLen, MEM_COMMIT, PAGE_READWRITE)) == NULL){
		//VirtualAllocEX Error
		MessageBox(NULL, _T("VirtualAllocEx"), _T("Error"), MB_OK);
		return -1;
	}

	//WriteProcessMemory
	if (WriteProcessMemory(hTargetProc, memAddr, (PVOID)dllPath, dllPathLen, NULL) == 0){
		//WriteProcessMemory Error
		MessageBox(NULL, _T("WriteProcessMemory"), _T("Error"), MB_OK);
		return -1;
	}

	FARPROC LoadLibFunc;
	if ((LoadLibFunc = GetProcAddress(GetModuleHandle(_T("Kernel32")), "LoadLibraryW")) == NULL){
		//GetProcAddress Error
		MessageBox(NULL, _T("GetProcAddress"), _T("Error"), MB_OK);
		return -1;
	}

	//CreateRemoteThread
	HANDLE hThread;
	if ((hThread = CreateRemoteThread(hTargetProc, NULL, 0, (PTHREAD_START_ROUTINE)LoadLibFunc, memAddr, 0, NULL)) == NULL){
		//CreateRemoteThread Error
		MessageBox(NULL, _T("CreateRemoteThread"), _T("Error"), MB_OK);
		return -1;
	}

	printf("Success\n");
	return 0;
}