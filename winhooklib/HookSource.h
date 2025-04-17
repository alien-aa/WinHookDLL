#ifndef HOOK_SOURCE_H
#define HOOK_SOURCE_H

#include "HookManager.h"
#include <windows.h>

extern decltype(&FindFirstFileA) originalFindFirstFileA;
extern decltype(&FindFirstFileW) originalFindFirstFileW;
extern decltype(&FindFirstFile) originalFindFirstFile;
extern decltype(&FindNextFileA) originalFindNextFileA;
extern decltype(&FindNextFileW) originalFindNextFileW;
extern decltype(&FindNextFile) originalFindNextFile;
extern decltype(&GetFileAttributesA) originalGetFileAttributesA;
extern decltype(&GetFileAttributesW) originalGetFileAttributesW;
extern decltype(&GetFileAttributes) originalGetFileAttributes;
extern decltype(&CreateFileA) originalCreateFileA;
extern decltype(&CreateFileW) originalCreateFileW;
extern decltype(&CreateFile) originalCreateFile;

HANDLE WINAPI Hooked_FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
HANDLE WINAPI Hooked_FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
HANDLE WINAPI Hooked_FindFirstFile(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
BOOL WINAPI Hooked_FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
BOOL WINAPI Hooked_FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
BOOL WINAPI Hooked_FindNextFile(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
DWORD WINAPI Hooked_GetFileAttributesA(LPCSTR lpFileName);
DWORD WINAPI Hooked_GetFileAttributesW(LPCWSTR lpFileName);
DWORD WINAPI Hooked_GetFileAttributes(LPCSTR lpFileName);
HANDLE WINAPI Hooked_CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);
HANDLE WINAPI Hooked_CreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);
HANDLE WINAPI Hooked_CreateFile(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);

#endif // HOOK_SOURCE_H