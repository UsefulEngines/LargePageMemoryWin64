// 
//
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
#include <stdlib.h>

//  NOTE the following additional linker input dependencies: 
//		user32.lib advapi32.lib


//////////////////////////////////////////////////////////////////////
// Globals and Function Declarations

wchar_t szName[]=L"LARGEPAGE";
typedef int (*GETLARGEPAGEMINIMUM)(void);

bool AdjustPrivilege(wchar_t* pszPrivilege, bool bEnablePrivilege); 
//bool SetCurrentPrivilege(wchar_t* pszPrivilege, bool bEnablePrivilege);

#ifdef _DEBUG
void _cdecl Trace(wchar_t *pszFormat, ...);		
#define TRACE  Trace
#else  
inline void _cdecl Trace(wchar_t *pszFormat, ...) {}
#define TRACE __noop
#endif // _DEBUG

// Some utility functions that might be moved to a header file if this weren't a sample.
int DisplayMessage(wchar_t *pszMessage);
int DisplayMessageVarArgs(wchar_t *pszFormat, ...);
int DisplayMessage(DWORD dwErrorCode);
bool ValidOptions(int argc, wchar_t *argv[]);
void DisplayUsage(wchar_t *progname);

// use these as default program arguments
bool bDisplayToConsole = true;
unsigned nNumPages = 16;        


////////////////////////////////////////////////////////////////////////////////
// 													THE MAIN FUNCTION
//
int _tmain(int argc, wchar_t* argv[])
{
	int nret = -1; 
  SIZE_T size = 0;
  SIZE_T bytes = 0;
  GETLARGEPAGEMINIMUM pGetLargePageMinimum = NULL;
  HINSTANCE  hDll = NULL;      

	if (ValidOptions(argc, argv) == false)
		return 0;
	
 	try
	{
 		// call succeeds only on Windows Server 2003 SP1 or later
  	hDll = LoadLibrary(L"kernel32.dll");  
  	if (hDll == NULL)
        throw(L"LoadLibrary");

    pGetLargePageMinimum = (GETLARGEPAGEMINIMUM)GetProcAddress(hDll, "GetLargePageMinimum");
    if (pGetLargePageMinimum == NULL)
        throw(L"GetProcAddress");

    size = (*pGetLargePageMinimum)();

    FreeLibrary(hDll);

		if (AdjustPrivilege(L"SeLockMemoryPrivilege", true) == true)
		{
			// Make sure requested size is aligned with page size
			bytes = size * nNumPages;	
			// Allocate virtual memory
			LPVOID p = VirtualAlloc(NULL, bytes, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);
			
			// TODO something with the memory
		
		  AdjustPrivilege(L"SeLockMemoryPrivilege", false);
		}
	}
	catch (DWORD dwErrCode)
	{
		DisplayMessage(dwErrCode);
		nret = dwErrCode;
	}
	catch (wchar_t *pszMessage)
	{
		nret = ::GetLastError();
		DisplayMessageVarArgs(L"Error : %ws : %08X", pszMessage, nret);
  }
	catch (...)
	{
		nret = ::GetLastError();
		DisplayMessageVarArgs(L"Error : Unexpected Exception : %08X", nret);
	}

	return nret;
}




////////////////////////////////////////////////////////////////////////
//			AdjustPrivilege
//			
//			LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
//			bool bEnablePrivilege   // to enable or disable privilege


bool AdjustPrivilege(wchar_t* pszPrivilege, bool bEnablePrivilege) 
{
		TOKEN_PRIVILEGES tp;
		TOKEN_PRIVILEGES prevtp;
		LUID luid;
		HANDLE hToken;
			
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) == 0)
		{
				DisplayMessageVarArgs(L"Error : OpenProcessToken : %08X", ::GetLastError());
				return false;
		}
		
		if (!LookupPrivilegeValue(NULL,           // lookup privilege on local system
        											pszPrivilege,   // privilege to lookup 
        											&luid))        	// receives LUID of privilege
		{
				DisplayMessageVarArgs(L"Error : LookupPrivilegeValue : %08X", ::GetLastError());
				return false;
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		if (bEnablePrivilege)
    		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		else
    		tp.Privileges[0].Attributes = 0;

		// Enable the privilege or disable all privileges.

		if (!AdjustTokenPrivileges(hToken, 
       												 FALSE, 
       												 &tp, 
       												 sizeof(TOKEN_PRIVILEGES), 
       												 (PTOKEN_PRIVILEGES) NULL, 
       											   (PDWORD) NULL ))
		{
				DisplayMessageVarArgs(L"Error : AdjustTokenPrivileges : %08X", ::GetLastError());
				return false;
		}

		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)	
		{
				DisplayMessage(L"Error : AdjustPrivilege : The token does not have the specified privilege.");
		    return false;
		} 

		return true;
}


/* ANOTHER SAMPLE SAME FUNCTIONALITY AS ABOVE...
bool SetCurrentPrivilege(wchar_t* pszPrivilege, bool bEnablePrivilege )
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tp, tpPrevious;
	DWORD cbPrevious = sizeof( TOKEN_PRIVILEGES );
	BOOL bSuccess = FALSE;

	if ( ! LookupPrivilegeValue( NULL, pszPrivilege, &luid ) )
		return FALSE;

	if( ! OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken ) )
		return FALSE;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges( hToken, FALSE, &tp, sizeof( TOKEN_PRIVILEGES ), &tpPrevious, &cbPrevious );

	if ( GetLastError() == ERROR_SUCCESS )
	{
		tpPrevious.PrivilegeCount = 1;
		tpPrevious.Privileges[0].Luid = luid;

		if ( bEnablePrivilege )
			tpPrevious.Privileges[0].Attributes |= ( SE_PRIVILEGE_ENABLED );
		else
			tpPrevious.Privileges[0].Attributes &= ~( SE_PRIVILEGE_ENABLED );

		AdjustTokenPrivileges( hToken, FALSE, &tpPrevious, cbPrevious, NULL, NULL );

		if ( GetLastError() == ERROR_SUCCESS )
			bSuccess=TRUE;
	}

	CloseHandle( hToken );

	return bSuccess;
}
*/





//=================================================================================
//  UTILITY FUNCTIONS

void DisplayUsage(wchar_t *progname)
{
	DisplayMessageVarArgs(	L"Usage:\n\n  %ws [-n] [-g] [-?] \n\n"	
					L"  -n # (i.e. # = number of pages; e.g. 32)\n"
					L"  -g Display messages using GUI\n"
					L"  -? Display this message\n"						
					L"\t(note:  no arguments creates a process with defaults (i.e. n = 16)\n",
					L"\t(ex:  %ws -n 64)\n",
					progname, 
					progname);
}


bool ValidOptions(int argc, wchar_t *argv[]) 
{
	bool bRet = true;
  
	for( int i = 1; i < argc; i++ ) 
	{
		if( (argv[i][0] == L'-') || (argv[i][0] == L'/') ) 
		{
			switch( tolower(argv[i][1]) ) 
			{
			case L'n':	// number of pages
				i++;
				if ((i < argc) && (lstrlen(argv[i]) > 0))
				{ 
					// TODO : add check for numeric string
					nNumPages = _wtoi(argv[i]);
				}
				break;

			case L'g':
				bDisplayToConsole = false;
				break;

			case L'?':
				DisplayUsage(argv[0]);
				return(false);

			default:	// unrecognized option
				DisplayUsage(argv[0]);
				return(false);
			}
		}
	}   
	return(bRet);
}



// ===============================================================================
// Error Message and Debug Message Handling Functions 

static wchar_t msg[2048];	

int DisplayMessage(wchar_t *pszMessage)
{
	if ((bDisplayToConsole) && (pszMessage != NULL))
	{
		_ftprintf_s(stdout,  L"\n%s\n", pszMessage);
		return 0;
	}
	else
	return MessageBox(NULL, pszMessage, L"Info", 
		   MB_OK | MB_ICONINFORMATION);
}

int DisplayMessageVarArgs(wchar_t *lpszFormat, ...)
{
	int nRet = 0;
	va_list args;
	va_start(args, lpszFormat);

	int nBuf = 0;
	nBuf = ::_vsntprintf_s(msg, (sizeof(msg) / sizeof(wchar_t)) - 1, lpszFormat, args);


	if (bDisplayToConsole)
		_ftprintf(stdout, L"\n%s\n", msg);
	else
		nRet = ::MessageBox(NULL, msg, L"Info", MB_OK | MB_ICONINFORMATION);
	va_end(args);
	return nRet;
}

int DisplayMessage(DWORD dwErrCode) 
{ 
    wchar_t* pszMsgBuf;
    int nRet = 0;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        					FORMAT_MESSAGE_FROM_SYSTEM,
        					NULL,
        					dwErrCode,
        					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        					(LPTSTR) &pszMsgBuf,
        					0, NULL );

		if (pszMsgBuf)
				nRet = DisplayMessage(pszMsgBuf);
				
    LocalFree(pszMsgBuf);
    return nRet;
}


#ifdef _DEBUG
void _cdecl Trace(wchar_t *lpszFormat, ...)
{
	va_list args;
	va_start(args, lpszFormat);

	int nBuf = 0;
	nBuf = ::_vsntprintf_s(msg, (sizeof(msg) / sizeof(wchar_t)) - 1, lpszFormat, args);

	::OutputDebugString(msg);
	va_end(args);
	return;
}
#endif // _DEBUG


