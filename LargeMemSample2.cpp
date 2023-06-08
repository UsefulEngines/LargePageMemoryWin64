
#define STRICT
#define WIN32_LEAN_AND_MEAN	

#ifndef WINVER				
#define WINVER 0x0501		
#endif

#ifndef _WIN32_WINNT		                   
#define _WIN32_WINNT 0x0501	
#endif						


#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#define BUF_SIZE 65536

wchar_t szName[]=L"LARGEPAGE";
typedef int (*GETLARGEPAGEMINIMUM)(void);

void DisplayError(wchar_t* pszAPI, DWORD dwError)
{
    LPVOID lpvMessageBuffer;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            NULL, dwError,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), //The user default language
            (LPTSTR)&lpvMessageBuffer, 0, NULL);

    //... now display this string
    _ftprintf(stdout, L"ERROR: API        = %s.\n", pszAPI);
    _ftprintf(stdout, L"       error code = %d.\n", dwError);
    _ftprintf(stdout, L"       message    = %s.\n", (wchar_t *)lpvMessageBuffer);

    // Free the buffer allocated by the system
    LocalFree(lpvMessageBuffer);

    ExitProcess(GetLastError());
}

void Privilege(wchar_t* pszPrivilege, BOOL bEnable)
{
    HANDLE           hToken;
    TOKEN_PRIVILEGES tp;

    // open process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        DisplayError(L"OpenProcessToken", GetLastError());

    // get the luid
    if (!LookupPrivilegeValue(NULL, pszPrivilege, &tp.Privileges[0].Luid))
        DisplayError(L"LookupPrivilegeValue", GetLastError());

    tp.PrivilegeCount = 1;

    // enable or disable privilege
    if (bEnable)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // enable or disable privilege
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, 0))
        DisplayError(L"AdjustTokenPrivileges", GetLastError());

    // close the handle
    if (!CloseHandle(hToken))
        DisplayError(L"CloseHandle", GetLastError());
}

void _tmain(void)
{
    HANDLE hMapFile;
    LPCTSTR pBuf;
    SIZE_T size;
    GETLARGEPAGEMINIMUM pGetLargePageMinimum;
    HINSTANCE  hDll;      
	
    // call succeeds only on Windows Server 2003 SP1 or later
    hDll = LoadLibrary(L"kernel32.dll");  
    if (hDll == NULL)
        DisplayError(L"LoadLibrary", GetLastError());

    pGetLargePageMinimum = (GETLARGEPAGEMINIMUM)GetProcAddress(hDll, "GetLargePageMinimum");
    if (pGetLargePageMinimum == NULL)
        DisplayError(L"GetProcAddress", GetLastError());

    size = (*pGetLargePageMinimum)();

    FreeLibrary(hDll);

    _ftprintf(stdout, L"Page Size: %u\n", size);

    // enable the required privilege
    Privilege(L"SeLockMemoryPrivilege", TRUE);

    hMapFile = CreateFileMapping(
         INVALID_HANDLE_VALUE,    // use paging file
         NULL,                    // default security 
         PAGE_READWRITE | SEC_COMMIT | SEC_LARGE_PAGES,
         0,                       // max. object size 
         size,                    // buffer size  
         szName);                 // name of mapping object
 
    if (hMapFile == NULL) 
        DisplayError(L"CreateFileMapping", GetLastError());
    else
        _ftprintf(stdout, L"File mapping object successfulyl created.\n");

    // disable the privilege
    Privilege(L"SeLockMemoryPrivilege", FALSE);

    pBuf = (LPTSTR) MapViewOfFile(hMapFile,   // handle to map object
         FILE_MAP_ALL_ACCESS, // read/write permission
         0,                   
         0,                   
         BUF_SIZE);           
 
    if (pBuf == NULL) 
        DisplayError(L"MapViewOfFile", GetLastError());
    else
        _ftprintf(stdout, L"View of file successfully mapped.\n");
	
    // do nothing, clean up on exit
    UnmapViewOfFile(pBuf);
    CloseHandle(hMapFile);
}

