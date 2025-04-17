#include "pch.h"
#include "HookManager.h"
#include "HookSource.h"
#include <iostream>

#define KERNEL32 L"kernel32.dll"

extern "C" void hook_body(void);


HookManager::HookManager() : library(LoadLibraryW(KERNEL32)) {}

HookManager::~HookManager() {
    clear();
}

HookManager& HookManager::get_instance() {
    static HookManager instance;
    return instance;
}

void HookManager::set_hide(const std::string& hide_name) {
    FARPROC findFirstFileA = GetProcAddress(library, "FindFirstFileA");
    FARPROC findFirstFileW = GetProcAddress(library, "FindFirstFileW");
    FARPROC findNextFileA = GetProcAddress(library, "FindNextFileA");
    FARPROC findNextFileW = GetProcAddress(library, "FindNextFileW");
    FARPROC getFileAttributesA = GetProcAddress(library, "GetFileAttributesA");
    FARPROC getFileAttributesW = GetProcAddress(library, "GetFileAttributesW");
    FARPROC createFileA = GetProcAddress(library, "CreateFileA");
    FARPROC createFileW = GetProcAddress(library, "CreateFileW");

    HookPatch* patchFindFirstFileA = new HookPatch(findFirstFileA, Hooked_FindFirstFileA, hide_name);
    HookPatch* patchFindFirstFileW = new HookPatch(findFirstFileW, Hooked_FindFirstFileW, hide_name);
    HookPatch* patchFindNextFileA = new HookPatch(findNextFileA, Hooked_FindNextFileA, hide_name);
    HookPatch* patchFindNextFileW = new HookPatch(findNextFileW, Hooked_FindNextFileW, hide_name);
    HookPatch* patchGetFileAttributesA = new HookPatch(getFileAttributesA, Hooked_GetFileAttributesA, hide_name);
    HookPatch* patchGetFileAttributesW = new HookPatch(getFileAttributesW, Hooked_GetFileAttributesW, hide_name);
    HookPatch* patchCreateFileA = new HookPatch(createFileA, Hooked_CreateFileA, hide_name);
    HookPatch* patchCreateFileW = new HookPatch(createFileW, Hooked_CreateFileW, hide_name);

    if (patchFindFirstFileA->install_hide()) hooks[hide_name].push_back(patchFindFirstFileA);
    if (patchFindFirstFileW->install_hide()) hooks[hide_name].push_back(patchFindFirstFileW);
    if (patchFindNextFileA->install_hide()) hooks[hide_name].push_back(patchFindNextFileA);
    if (patchFindNextFileW->install_hide()) hooks[hide_name].push_back(patchFindNextFileW);
    if (patchGetFileAttributesA->install_hide()) hooks[hide_name].push_back(patchGetFileAttributesA);
    if (patchGetFileAttributesW->install_hide()) hooks[hide_name].push_back(patchGetFileAttributesW);
    if (patchCreateFileA->install_hide()) hooks[hide_name].push_back(patchCreateFileA);
    if (patchCreateFileW->install_hide()) hooks[hide_name].push_back(patchCreateFileW);
}

uint64_t HookManager::set_hook(const std::string& func_name) {
    FARPROC orig_addr = GetProcAddress(library, func_name.c_str());
    FARPROC orig_addr_base = GetProcAddress(LoadLibraryW(L"kernelbase.dll"), func_name.c_str());

    HookPatch* patch = new HookPatch(orig_addr, orig_addr_base, hook_body);
    patch->set_hook_name(func_name);
    if (!patch->install_hook()) return NULL;
    auto result = patch->get_hook_addr();
    if (result != nullptr)
    {
        hooks[func_name].push_back(patch);
        return reinterpret_cast<uint64_t>(result);
    }

    return NULL;
}

void HookManager::clear() {
    for (auto& pair : hooks) {
        for (auto hook : pair.second) {
            delete hook;
        }
    }
    hooks.clear();

    if (library) {
        FreeLibrary(library);
    }
}

bool HookManager::is_file_hidden(const std::string& file_name) {
    for (const auto& pair : hooks) {
        if (pair.first == file_name) {
            return true;
        }
    }
    return false;
}

HookPatch* HookManager::get_patch(const std::string& function_name) {
    for (const auto& pair : hooks) {
        for (auto patch : pair.second) {
            if (patch->get_hook_name() == function_name) {
                return patch;
            }
        }
    }
    return nullptr;
}