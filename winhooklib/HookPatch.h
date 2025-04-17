#ifndef HOOK_PATCH
#define HOOK_PATCH
#include <windows.h>
#include <string>

class HookPatch {
public:
    HookPatch();
    HookPatch(void* orig, void* hook, const std::string& hidden);
    HookPatch(void* orig, void* base, void* hook);
    ~HookPatch();

    bool install_hide();
    bool remove_hide();
    bool install_hook();
    void* get_hook_addr();


    template <typename T>
    T getOriginalFunction() const {
        if (!trampoline) return nullptr;
        return reinterpret_cast<T>(trampoline);
    }

    const std::string& get_hook_name() const;
    void set_hook_name(const std::string& name);


private:
    void* my_alloc(void* desiredLocation);
    void memcpy_jmp(void* from_addr, void* to_addr);

    std::string hidden_file;
    std::string hook_name;
    void* orig_addr;
    void* base_addr;
    void* hook_addr;
    void* trampoline;
    static constexpr size_t HOOK_SIZE = 14;
    BYTE saved_bytes[HOOK_SIZE];
    bool installed;
};

#endif // HOOK_PATCH