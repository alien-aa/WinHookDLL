#include "pch.h"
#include "HookPatch.h"

HookPatch::HookPatch() 
    : hidden_file(), orig_addr(nullptr), base_addr(nullptr), 
    hook_addr(nullptr), installed(false), trampoline(nullptr),
    hook_name()
{}

HookPatch::HookPatch(void* orig, void* hook, const std::string& hidden)
    : hidden_file(hidden), orig_addr(orig), base_addr(nullptr), 
    hook_addr(hook), installed(false), trampoline(nullptr),
    hook_name("Unknown") 
{}

HookPatch::HookPatch(void* orig, void* base, void* hook)
    : hidden_file(), orig_addr(orig), base_addr(base),
    hook_addr(hook), installed(false), trampoline(nullptr),
    hook_name("Unknown") 
{}

HookPatch::~HookPatch() {}

bool HookPatch::install_hide() {
    if (!orig_addr || installed) return false;

    trampoline = VirtualAlloc(NULL, HOOK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline) {
        return false;
    }

    memcpy(saved_bytes, orig_addr, HOOK_SIZE);
    memcpy(trampoline, orig_addr, HOOK_SIZE);

    BYTE* trampoline_jmp = (BYTE*)trampoline + HOOK_SIZE;
    DWORD relative_jump = ((DWORD_PTR)(orig_addr) + HOOK_SIZE - (DWORD_PTR)(trampoline_jmp)) - 5;
    *trampoline_jmp++ = 0xE9;
    *(DWORD*)trampoline_jmp = relative_jump;

    DWORD protect_status;
    if (!VirtualProtect(orig_addr, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &protect_status)) {
        return false;
    }

    BYTE new_bytes[HOOK_SIZE] = { 0 };
    memcpy(new_bytes, "\xFF\x25\x00\x00\x00\x00", 6);
    *(void**)(new_bytes + 6) = hook_addr;
    memcpy(orig_addr, new_bytes, HOOK_SIZE);

    if (!VirtualProtect(orig_addr, HOOK_SIZE, protect_status, &protect_status)) {
        return false;
    }

    installed = true;
    return true;
}

bool HookPatch::remove_hide() {
    if (!installed || !trampoline) return false;

    DWORD protect_status;
    if (!VirtualProtect(orig_addr, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &protect_status)) {
        return false;
    }
    memcpy(orig_addr, saved_bytes, HOOK_SIZE);
    if (!VirtualProtect(orig_addr, HOOK_SIZE, protect_status, &protect_status)) {
        return false;
    }

    if (trampoline) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        trampoline = nullptr;
    }

    installed = false;
    return true;
}

bool HookPatch::install_hook()
{
    if (!orig_addr || !base_addr || installed) return false;

    void* mem_near_orig = my_alloc(orig_addr);
    if (mem_near_orig == nullptr) return false;
    memcpy_jmp(mem_near_orig, hook_addr);

    DWORD protect_status;
    if (!VirtualProtect(orig_addr, 1024, PAGE_EXECUTE_READWRITE, &protect_status)) return false;
    memcpy(saved_bytes, orig_addr, HOOK_SIZE);
    memcpy_jmp(orig_addr, mem_near_orig);

    if (!VirtualProtect(orig_addr, HOOK_SIZE, protect_status, &protect_status)) return false;

    void* mem_near_hook = my_alloc(hook_addr);
    if (mem_near_hook == nullptr) return false;

    void* mem_near_base = my_alloc(base_addr);
    if (mem_near_base == nullptr) return false;

    memcpy_jmp(mem_near_hook, mem_near_base);
    memcpy_jmp(mem_near_base, base_addr);

    trampoline = mem_near_hook;

    installed = true;

    return true;
}

void* HookPatch::get_hook_addr()
{
    return trampoline;
}

const std::string& HookPatch::get_hook_name() const {
    return hook_name;
}

void HookPatch::set_hook_name(const std::string& name) {
    hook_name = name;
}

void* HookPatch::my_alloc(void* desiredLocation) {
    SYSTEM_INFO systemDetails;
    GetSystemInfo(&systemDetails);

    const uint64_t MEMORY_PAGE = systemDetails.dwPageSize;
    uint64_t baseAddr = (uint64_t(desiredLocation) & ~(MEMORY_PAGE - 1));
    uint64_t lowerBound = min(baseAddr - 0x7FFFFF00, (uint64_t)systemDetails.lpMinimumApplicationAddress);
    uint64_t upperBound = max(baseAddr + 0x7FFFFF00, (uint64_t)systemDetails.lpMaximumApplicationAddress);

    uint64_t initialPage = (baseAddr - (baseAddr % MEMORY_PAGE));
    uint64_t offsetMultiplier = 1;

    while (true) {
        uint64_t currentOffset = offsetMultiplier * MEMORY_PAGE;
        uint64_t higherAddr = initialPage + currentOffset;
        uint64_t lowerAddr = (initialPage > currentOffset) ? initialPage - currentOffset : 0;
        bool shouldTerminate = higherAddr > upperBound && lowerAddr < lowerBound;

        if (higherAddr < upperBound) {
            void* allocatedMemory = VirtualAlloc((void*)higherAddr, MEMORY_PAGE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (allocatedMemory)
                return allocatedMemory;
        }

        if (lowerAddr > lowerBound) {
            void* allocatedMemory = VirtualAlloc((void*)lowerAddr, MEMORY_PAGE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (allocatedMemory != nullptr)
                return allocatedMemory;
        }
        offsetMultiplier++;

        if (shouldTerminate) {
            break;
        }
    }

    return nullptr;
}

void HookPatch::memcpy_jmp(void* from_addr, void* to_addr)
{
    uint8_t* code = (uint8_t*)from_addr;
    code[0] = 0xFF; // JMP instruction
    code[1] = 0x25; // ModR/M byte
    *((uint32_t*)(code + 2)) = 0; // Offset
    *((uint64_t*)(code + 6)) = (uint64_t)to_addr; // Target address
}