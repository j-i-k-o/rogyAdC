#include <windows.h>
#include <tchar.h>

int WINAPI WinMain(
	HINSTANCE hInstance, 
	HINSTANCE hPrevInstance, 
	LPSTR lpCmdLine,         
	int nCmdShow 
	){
	MessageBoxW(NULL, _T("�i���ǂ��ł���"), _T("1"), MB_OK);
	MessageBoxW(NULL, _T("�i���ǂ��ł���"), _T("2"), MB_OK);
	MessageBoxW(NULL, _T("�i���ǂ��ł���"), _T("3"), MB_OK);
}