#pragma once
#include <Windows.h>
#include "base\helpers.h"
#include <wininet.h>
#include <wchar.h>
#include <stdio.h>
#include <stringapiset.h>
#include <sspi.h>
#include <process.h>
#include <WinUser.h>
/**
* For the debug build we want:
*   a) Include the mock-up layer
*   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
*      is linked against the the debug build.
*/
#ifndef _DEBUG
WINBASEAPI int __cdecl MSVCRT$sprintf(char* stream, const char* __format, ...);
DECLSPEC_IMPORT PCHAR __cdecl MSVCRT$strstr(const char* haystack, const char* needle);
DECLSPEC_IMPORT PCHAR __cdecl MSVCRT$strchr(const char* haystack, int needle);
DECLSPEC_IMPORT void __cdecl MSVCRT$_endthreadex(unsigned);
DECLSPEC_IMPORT uintptr_t __cdecl MSVCRT$_beginthreadex(void*, unsigned, unsigned(__stdcall*)(void*), void*, unsigned, unsigned*);
#define sprintf MSVCRT$sprintf
#define strstr MSVCRT$strstr
#define strchr MSVCRT$strchr
#endif

// ==================== DYNAMIC FUNCTION RESOLUTION DECLARATIONS ====================

// KERNEL32
DFR(KERNEL32, GetLastError);
DFR(KERNEL32, HeapAlloc);
DFR(KERNEL32, HeapReAlloc);
DFR(KERNEL32, GetProcessHeap);
DFR(KERNEL32, HeapFree);
DFR(KERNEL32, lstrcpyA);
DFR(KERNEL32, lstrcmpA);
DFR(KERNEL32, lstrcmpiA);
DFR(KERNEL32, CloseHandle);
DFR(KERNEL32, WriteFile);
DFR(KERNEL32, CreateFileA);
DFR(KERNEL32, AddVectoredExceptionHandler);
DFR(KERNEL32, GetExitCodeThread);
DFR(KERNEL32, RemoveVectoredExceptionHandler);
DFR(KERNEL32, WaitForSingleObject);
DFR(KERNEL32, MultiByteToWideChar);
DFR(KERNEL32, WideCharToMultiByte);

// MSVCRT
DFR(MSVCRT, strlen);
DFR(MSVCRT, memcpy);
DFR(MSVCRT, memset);
DFR(MSVCRT, memcmp);
DFR(MSVCRT, memmove);
DFR(MSVCRT, strcpy);
DFR(MSVCRT, strncpy);
DFR(MSVCRT, strcmp);
DFR(MSVCRT, strncmp);
DFR(MSVCRT, _strnicmp);
DFR(MSVCRT, free);
DFR(MSVCRT, vsnprintf);
DFR(MSVCRT, _snprintf);
DFR(MSVCRT, atoi);
DFR(MSVCRT, strtok_s);
DFR(MSVCRT, _strtoui64);
DFR(MSVCRT, _endthreadex);
DFR(MSVCRT, _beginthreadex);
DFR(MSVCRT, wcslen);
// KERNEL32 or USER32 section - add:
DFR(USER32, wsprintfW);


// SECUR32
DFR(SECUR32, AcquireCredentialsHandleA);
DFR(SECUR32, InitializeSecurityContextA);
DFR(SECUR32, FreeContextBuffer);
DFR(SECUR32, DeleteSecurityContext);
DFR(SECUR32, FreeCredentialsHandle);

// CRYPT32
DFR(CRYPT32, CryptBinaryToStringA);

// WININET
DFR(WININET, InternetOpenA);
DFR(WININET, InternetConnectA);
DFR(WININET, HttpOpenRequestA);
DFR(WININET, InternetSetOptionA);
DFR(WININET, HttpAddRequestHeadersA);
DFR(WININET, HttpSendRequestA);
DFR(WININET, HttpQueryInfoA);
DFR(WININET, InternetQueryDataAvailable);
DFR(WININET, InternetReadFile);
DFR(WININET, InternetCloseHandle);
DFR(WININET, InternetCrackUrlA);
DFR(WININET, InternetGetCookieA);
DFR(WININET, InternetSetCookieA);

// OLE32
DFR(OLE32, CoInitializeEx);
DFR(OLE32, CoUninitialize);
DFR(OLE32, CoCreateInstance);
DFR(OLE32, CLSIDFromString);
DFR(OLE32, IIDFromString);
DFR(OLE32, CoTaskMemFree);

// ==================== MACRO DEFINITIONS ====================

// KERNEL32
#define GetLastError KERNEL32$GetLastError
#define HeapFree KERNEL32$HeapFree
#define HeapAlloc KERNEL32$HeapAlloc
#define HeapReAlloc KERNEL32$HeapReAlloc
#define GetProcessHeap KERNEL32$GetProcessHeap
#define lstrcpyA KERNEL32$lstrcpyA
#define lstrcmpA KERNEL32$lstrcmpA
#define lstrcmpiA KERNEL32$lstrcmpiA
#define CloseHandle KERNEL32$CloseHandle
#define CreateFileA KERNEL32$CreateFileA
#define WriteFile KERNEL32$WriteFile
#define AddVectoredExceptionHandler KERNEL32$AddVectoredExceptionHandler
#define GetExitCodeThread KERNEL32$GetExitCodeThread
#define RemoveVectoredExceptionHandler KERNEL32$RemoveVectoredExceptionHandler
#define WaitForSingleObject KERNEL32$WaitForSingleObject
#define MultiByteToWideChar KERNEL32$MultiByteToWideChar
#define WideCharToMultiByte KERNEL32$WideCharToMultiByte
// In macros section:
#define wsprintfW USER32$wsprintfW


// MSVCRT
#define strlen MSVCRT$strlen
#define memcpy MSVCRT$memcpy
#define memset MSVCRT$memset
#define memcmp MSVCRT$memcmp
#define memmove MSVCRT$memmove
#define strcpy MSVCRT$strcpy
#define strncpy MSVCRT$strncpy
#define strcmp MSVCRT$strcmp
#define strncmp MSVCRT$strncmp
#define _strnicmp MSVCRT$_strnicmp
#define free MSVCRT$free
#define vsnprintf MSVCRT$vsnprintf
#define _snprintf MSVCRT$_snprintf
#define snprintf MSVCRT$_snprintf
#define atoi MSVCRT$atoi
#define strtok_s MSVCRT$strtok_s
#define _strtoui64 MSVCRT$_strtoui64
#define _endthreadex MSVCRT$_endthreadex
#define _beginthreadex MSVCRT$_beginthreadex
#define wcslen MSVCRT$wcslen

// SECUR32
#define AcquireCredentialsHandleA SECUR32$AcquireCredentialsHandleA
#define InitializeSecurityContextA SECUR32$InitializeSecurityContextA
#define FreeContextBuffer SECUR32$FreeContextBuffer
#define DeleteSecurityContext SECUR32$DeleteSecurityContext
#define FreeCredentialsHandle SECUR32$FreeCredentialsHandle

// CRYPT32
#define CryptBinaryToStringA CRYPT32$CryptBinaryToStringA

// WININET
#define InternetOpenA WININET$InternetOpenA
#define InternetConnectA WININET$InternetConnectA
#define HttpOpenRequestA WININET$HttpOpenRequestA
#define InternetSetOptionA WININET$InternetSetOptionA
#define HttpAddRequestHeadersA WININET$HttpAddRequestHeadersA
#define HttpSendRequestA WININET$HttpSendRequestA
#define HttpQueryInfoA WININET$HttpQueryInfoA
#define InternetQueryDataAvailable WININET$InternetQueryDataAvailable
#define InternetReadFile WININET$InternetReadFile
#define InternetCloseHandle WININET$InternetCloseHandle
#define InternetCrackUrlA WININET$InternetCrackUrlA
#define InternetGetCookieA WININET$InternetGetCookieA
#define InternetSetCookieA WININET$InternetSetCookieA

// OLE32
#define CoInitializeEx OLE32$CoInitializeEx
#define CoUninitialize OLE32$CoUninitialize
#define CoCreateInstance OLE32$CoCreateInstance
#define CLSIDFromString OLE32$CLSIDFromString
#define IIDFromString OLE32$IIDFromString
#define CoTaskMemFree OLE32$CoTaskMemFree

// ==================== CUSTOM MEMORY MANAGEMENT MACROS ====================
#define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)
#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intReAlloc(ptr,size) HeapReAlloc(GetProcessHeap(), 0, ptr, size)