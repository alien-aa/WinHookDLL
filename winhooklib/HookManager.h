#ifndef HOOKMANAGER_H
#define HOOKMANAGER_H

#include "HookPatch.h"
#include <windows.h>
#include <map>
#include <vector>
#include <string>

class HookManager {
public:
    static HookManager& get_instance();

    void set_hide(const std::string& hide_name);
    uint64_t set_hook(const std::string& func_name);
    void clear();
    bool is_file_hidden(const std::string& file_name);

    HookPatch* get_patch(const std::string& function_name);


private:
    HookManager();
    ~HookManager();

    HMODULE library;
    std::map<std::string, std::vector<HookPatch*>> hooks;
};

#endif // HOOKMANAGER_H