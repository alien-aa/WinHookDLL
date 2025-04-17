#include "pch.h"
#include "HookSource.h"
#include "HookManager.h"
#include <iostream>
#include <string>


HANDLE WINAPI Hooked_FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) {
    auto patch = HookManager::get_instance().get_patch("FindFirstFileA");
    if (!patch) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return INVALID_HANDLE_VALUE;
    }
    auto originalFindFirstFileA = patch->getOriginalFunction<decltype(&FindFirstFileA)>();
    if (!originalFindFirstFileA) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return INVALID_HANDLE_VALUE;
    }
    HANDLE hFind = originalFindFirstFileA(lpFileName, lpFindFileData);
    if (hFind != INVALID_HANDLE_VALUE) {
        if (HookManager::get_instance().is_file_hidden(lpFileName)) {
            CloseHandle(hFind);
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }
        while (HookManager::get_instance().is_file_hidden(lpFindFileData->cFileName)) {
            if (!FindNextFileA(hFind, lpFindFileData)) {
                CloseHandle(hFind);
                return INVALID_HANDLE_VALUE;
            }
        }
    }
    return hFind;
}


HANDLE WINAPI Hooked_FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) {
    auto patch = HookManager::get_instance().get_patch("FindFirstFileW");
    if (!patch) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return INVALID_HANDLE_VALUE;
    }
    auto originalFindFirstFileW = patch->getOriginalFunction<decltype(&FindFirstFileW)>();
    if (!originalFindFirstFileW) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return INVALID_HANDLE_VALUE;
    }
    std::wstring wideFileName(lpFileName);
    std::string fileName(wideFileName.begin(), wideFileName.end());
    if (HookManager::get_instance().is_file_hidden(fileName)) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    HANDLE hFind = originalFindFirstFileW(lpFileName, lpFindFileData);
    if (hFind != INVALID_HANDLE_VALUE) {
        std::wstring wideFileName(lpFindFileData->cFileName);
        std::string fileName(wideFileName.begin(), wideFileName.end());
        while (HookManager::get_instance().is_file_hidden(fileName)) {
            if (!FindNextFileW(hFind, lpFindFileData)) {
                CloseHandle(hFind);
                return INVALID_HANDLE_VALUE;
            }
            wideFileName = lpFindFileData->cFileName;
            fileName = std::string(wideFileName.begin(), wideFileName.end());
        }
    }
    return hFind;
}


BOOL WINAPI Hooked_FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) {
    auto patch = HookManager::get_instance().get_patch("FindNextFileA");
    if (!patch) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
    }
    auto originalFindNextFileA = patch->getOriginalFunction<decltype(&FindNextFileA)>();
    if (!originalFindNextFileA) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
    }
    BOOL result = originalFindNextFileA(hFindFile, lpFindFileData);
    while (result && HookManager::get_instance().is_file_hidden(lpFindFileData->cFileName)) {
        result = originalFindNextFileA(hFindFile, lpFindFileData);
    }
    return result;
}


BOOL WINAPI Hooked_FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) {
    auto patch = HookManager::get_instance().get_patch("FindNextFileW");
    if (!patch) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
    }
    auto originalFindNextFileW = patch->getOriginalFunction<decltype(&FindNextFileW)>();
    if (!originalFindNextFileW) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
    }
    BOOL result = originalFindNextFileW(hFindFile, lpFindFileData);
    while (result) {
        std::wstring wideFileName(lpFindFileData->cFileName);
        std::string fileName(wideFileName.begin(), wideFileName.end());
        if (!HookManager::get_instance().is_file_hidden(fileName)) {
            break;
        }
        result = originalFindNextFileW(hFindFile, lpFindFileData);
    }
    return result;
}


DWORD WINAPI Hooked_GetFileAttributesA(LPCSTR lpFileName) {
    auto patch = HookManager::get_instance().get_patch("GetFileAttributesA");
    if (!patch) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return INVALID_FILE_ATTRIBUTES;
    }
    auto originalGetFileAttributesA = patch->getOriginalFunction<decltype(&GetFileAttributesA)>();
    if (!originalGetFileAttributesA) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return INVALID_FILE_ATTRIBUTES;
    }
    if (HookManager::get_instance().is_file_hidden(lpFileName)) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_FILE_ATTRIBUTES;
    }
    return originalGetFileAttributesA(lpFileName);
}


DWORD WINAPI Hooked_GetFileAttributesW(LPCWSTR lpFileName) {
    auto patch = HookManager::get_instance().get_patch("GetFileAttributesW");
    if (!patch) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return INVALID_FILE_ATTRIBUTES;
    }
    auto originalGetFileAttributesW = patch->getOriginalFunction<decltype(&GetFileAttributesW)>();
    if (!originalGetFileAttributesW) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return INVALID_FILE_ATTRIBUTES;
    }
    std::wstring wideFileName(lpFileName);
    std::string fileName(wideFileName.begin(), wideFileName.end());
    if (HookManager::get_instance().is_file_hidden(fileName)) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_FILE_ATTRIBUTES;
    }
    return originalGetFileAttributesW(lpFileName);
}


HANDLE WINAPI Hooked_CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    auto patch = HookManager::get_instance().get_patch("CreateFileA");
    if (!patch) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return INVALID_HANDLE_VALUE;
    }
    auto originalCreateFileA = patch->getOriginalFunction<decltype(&CreateFileA)>();
    if (!originalCreateFileA) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return INVALID_HANDLE_VALUE;
    }
    if (HookManager::get_instance().is_file_hidden(lpFileName)) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    return originalCreateFileA(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile
    );
}


HANDLE WINAPI Hooked_CreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    auto patch = HookManager::get_instance().get_patch("CreateFileW");
    if (!patch) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return INVALID_HANDLE_VALUE;
    }
    auto originalCreateFileW = patch->getOriginalFunction<decltype(&CreateFileW)>();
    if (!originalCreateFileW) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return INVALID_HANDLE_VALUE;
    }
    std::wstring wideFileName(lpFileName);
    std::string fileName(wideFileName.begin(), wideFileName.end());
    if (HookManager::get_instance().is_file_hidden(fileName)) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    return originalCreateFileW(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile
    );
}
