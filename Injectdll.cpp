#include <windows.h>
#include <tchar.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

#define MODULE_DLL "user32.dll"

typedef int (WINAPI *MESSAGEBOXA_FUNC)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
typedef int (WINAPI *MESSAGEBOXW_FUNC)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);

DWORD WINAPI apiHook(LPVOID pData);
int WINAPI Hook_MessageBoxA(
	HWND hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT uType
	);
int WINAPI Hook_MessageBoxW(
	HWND hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT uType
	);

BOOL APIENTRY DllMain(HANDLE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{
	HANDLE hThread;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		if ((hThread = CreateThread(NULL, 0,apiHook, (LPVOID)NULL, 0, NULL)) == NULL) {
			MessageBox(NULL, _TEXT("CreateThread"), _TEXT("Error"), MB_OK);
			return FALSE;
		}
		CloseHandle(hThread);
		break;
	}
	return TRUE;
}
DWORD WINAPI apiHook(LPVOID pData)
{
	MessageBox(NULL, _TEXT("I am DLL file."), _TEXT("message"), MB_OK);
	HMODULE baseAddr = GetModuleHandle(NULL);
	DWORD dwIdataSize;
	PIMAGE_IMPORT_DESCRIPTOR pImgDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(baseAddr, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &dwIdataSize);

	while (pImgDesc->Name){
		char* lpModule = (char*)(baseAddr) + pImgDesc->Name;
		if (!_stricmp(lpModule, MODULE_DLL)) {
			break;
		}
		pImgDesc++;
	}

	if (!pImgDesc->Name) {
		return -1;
	}

	PIMAGE_THUNK_DATA pIAT, pINT;
	pIAT = (PIMAGE_THUNK_DATA)((char*)baseAddr + pImgDesc->FirstThunk);
	pINT = (PIMAGE_THUNK_DATA)((char*)baseAddr + pImgDesc->OriginalFirstThunk);

	while (pIAT->u1.Function)
	{
		if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal))continue;
		PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)((char*)baseAddr + (DWORD)pINT->u1.AddressOfData);

		DWORD dwOldProtect;
		if (!_stricmp((const char*)pImportName->Name, "MessageBoxA"))
		{
			VirtualProtect(&pIAT->u1.Function, sizeof(DWORD), PAGE_READWRITE, &dwOldProtect);
			pIAT->u1.Function = (ULONGLONG)Hook_MessageBoxA;
			VirtualProtect(&pIAT->u1.Function, sizeof(DWORD), dwOldProtect, &dwOldProtect);
		}
		else if (!_stricmp((const char*)pImportName->Name, "MessageBoxW"))
		{
			VirtualProtect(&pIAT->u1.Function, sizeof(DWORD), PAGE_READWRITE, &dwOldProtect);
			pIAT->u1.Function = (ULONGLONG)Hook_MessageBoxW;
			VirtualProtect(&pIAT->u1.Function, sizeof(DWORD), dwOldProtect, &dwOldProtect);
		}

		pIAT++;pINT++;
	}
	MessageBox(NULL, _TEXT("Success"), _TEXT("Success"), MB_OK);
	return 0;
}

int WINAPI Hook_MessageBoxA(
	HWND hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT uType
	)
{
	MESSAGEBOXA_FUNC MsgBoxAProc;
	if ((MsgBoxAProc = (MESSAGEBOXA_FUNC)GetProcAddress(GetModuleHandle(_T("user32")), "MessageBoxA")) == NULL) {
		//GetProcAddress Error
	}
	return MsgBoxAProc(hWnd, "�ۂۂۂۂۂۂۂ�", lpCaption, uType);
}
int WINAPI Hook_MessageBoxW(
	HWND hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT uType
	)
{
	MESSAGEBOXW_FUNC MsgBoxWProc;
	if ((MsgBoxWProc = (MESSAGEBOXW_FUNC)GetProcAddress(GetModuleHandle(_T("user32")), "MessageBoxW")) == NULL) {
		//GetProcAddress Error
	}
	return MsgBoxWProc(hWnd, L"�ۂۂۂۂۂۂۂ�", lpCaption, uType);
}