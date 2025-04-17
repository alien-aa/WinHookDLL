#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include <atomic>
#include <filesystem>

#pragma comment(lib, "Ws2_32.lib")

typedef NTSTATUS(NTAPI* PNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

SOCKET g_socket = INVALID_SOCKET;
std::atomic<bool> g_running(true);

PNtQuerySystemInformation GetNtQuerySystemInformation() {
    HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
    if (!hNtDll) {
        return nullptr;
    }
    return reinterpret_cast<PNtQuerySystemInformation>(
        GetProcAddress(hNtDll, "NtQuerySystemInformation")
        );
}

struct ProgramArguments {
    int pid = -1;
    std::string processName;
    std::string functionToMonitor;
    std::string hideFilePath;
};

static bool ParseCommandLine(int argc, char* argv[], ProgramArguments& args) {
    if (argc < 2) {
        std::cerr << "[PROGRAM] Error: Not enough arguments." << std::endl;
        return false;
    }
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--pid") {
            if (i + 1 >= argc) {
                std::cerr << "[PROGRAM] Error: Missing value for --pid." << std::endl;
                return false;
            }
            try {
                args.pid = std::stoi(argv[++i]);
            }
            catch (...) {
                std::cerr << "[PROGRAM] Error: Invalid value for --pid." << std::endl;
                return false;
            }
        }
        else if (arg == "--name") {
            if (i + 1 >= argc) {
                std::cerr << "[PROGRAM] Error: Missing value for --name." << std::endl;
                return false;
            }
            args.processName = argv[++i];
            if (!args.processName.empty() && args.processName.back() == '\n') {
                args.processName.pop_back();
            }
            if (args.processName.empty()) {
                std::cerr << "[PROGRAM] Error: Invalid process name." << std::endl;
                return false;
            }
        }
        else if (arg == "--func") {
            if (i + 1 >= argc) {
                std::cerr << "[PROGRAM] Error: Missing value for --func." << std::endl;
                return false;
            }
            args.functionToMonitor = argv[++i];
        }
        else if (arg == "--hide") {
            if (i + 1 >= argc) {
                std::cerr << "[PROGRAM] Error: Missing file path for --hide." << std::endl;
                return false;
            }
            args.hideFilePath = argv[++i];
        }
        else {
            std::cerr << "[PROGRAM] Error: Unknown argument: " << arg << std::endl;
            return false;
        }
    }
    if (args.pid == -1 && args.processName.empty()) {
        std::cerr << "[PROGRAM] Error: Either --pid or --name must be specified." << std::endl;
        return false;
    }
    return true;
}

DWORD FindProcessByName(const std::string& processName) {
    auto NtQuerySystemInformation = GetNtQuerySystemInformation();
    if (!NtQuerySystemInformation) {
        std::cerr << "[PROGRAM] Failed to get NtQuerySystemInformation function." << std::endl;
        return 0;
    }
    PSYSTEM_PROCESS_INFORMATION pSysInfo = nullptr;
    NTSTATUS status;
    ULONG bufferSize = 0x1000;
    while (true) {
        pSysInfo = (PSYSTEM_PROCESS_INFORMATION)malloc(bufferSize);
        if (!pSysInfo) {
            std::cerr << "[PROGRAM] Failed to allocate memory for process information." << std::endl;
            return 0;
        }
        status = NtQuerySystemInformation(
            SystemProcessInformation,
            pSysInfo,
            bufferSize,
            &bufferSize
        );
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            free(pSysInfo);
            bufferSize *= 2;
            continue;
        }
        else if (!NT_SUCCESS(status)) {
            std::cerr << "[PROGRAM] NtQuerySystemInformation failed with status: " << status << std::endl;
            free(pSysInfo);
            return 0;
        }
        break;
    }
    PSYSTEM_PROCESS_INFORMATION pInfo = pSysInfo;
    while (pInfo) {
        if (pInfo->ImageName.Buffer) {
            std::wstring wideName(pInfo->ImageName.Buffer, pInfo->ImageName.Length / sizeof(wchar_t));
            std::string name(wideName.begin(), wideName.end());
            if (_stricmp(name.c_str(), processName.c_str()) == 0) {
                DWORD targetPID = (DWORD)pInfo->UniqueProcessId;
                free(pSysInfo);
                return targetPID;
            }
        }
        if (!pInfo->NextEntryOffset) break;
        pInfo = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)pInfo + pInfo->NextEntryOffset);
    }
    free(pSysInfo);
    return 0;
}

bool InjectDLLIntoProcess(DWORD targetPID, const std::string& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (!hProcess) {
        std::cerr << "[PROGRAM] Failed to open target process." << std::endl;
        return false;
    }
    LPVOID remoteString = VirtualAllocEx(hProcess, NULL, dllPath.size() + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteString) {
        std::cerr << "[PROGRAM] Failed to allocate memory in target process." << std::endl;
        CloseHandle(hProcess);
        return false;
    }
    if (!WriteProcessMemory(hProcess, remoteString, dllPath.c_str(), dllPath.size() + 1, NULL)) {
        std::cerr << "[PROGRAM] Failed to write DLL path to target process." << std::endl;
        VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, remoteString, 0, NULL);
    if (!hThread) {
        std::cerr << "[PROGRAM] Failed to create remote thread in target process." << std::endl;
        VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return true;
}

void PrintUsage() {
    std::cout << "[PROGRAM] Usage: monitor.exe [options]" << std::endl;
    std::cout << "[PROGRAM] Options:" << std::endl;
    std::cout << "[PROGRAM]   --pid <PID>              Target process selected by PID" << std::endl;
    std::cout << "[PROGRAM]   --name <NAME>            Target process selected by name" << std::endl;
    std::cout << "[PROGRAM]   --func <FUNCTION>        Function to monitor" << std::endl;
    std::cout << "[PROGRAM]   --hide <FILE_PATH>       Path to file to hide" << std::endl;
}

bool CreateSocketAndSendConfig(const ProgramArguments& args) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[PROGRAM] Failed to initialize Winsock." << std::endl;
        return false;
    }

    g_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_socket == INVALID_SOCKET) {
        std::cerr << "[PROGRAM] Failed to create socket: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return false;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr); 
    serverAddr.sin_port = htons(12345);

    if (connect(g_socket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "[PROGRAM] Failed to connect to server: " << WSAGetLastError() << std::endl;
        closesocket(g_socket);
        WSACleanup();
        return false;
    }

    std::ostringstream configStream;
    if (!args.functionToMonitor.empty()) {
        configStream << "hook:" << args.functionToMonitor << "\n";
    }
    if (!args.hideFilePath.empty()) {
        configStream << "hide:" << args.hideFilePath << "\n";
    }
    std::string config = configStream.str();

    if (send(g_socket, config.c_str(), config.size(), 0) == SOCKET_ERROR) {
        std::cerr << "[PROGRAM] Failed to send configuration: " << WSAGetLastError() << std::endl;
        closesocket(g_socket);
        WSACleanup();
        return false;
    }

    std::cout << "[PROGRAM] Configuration sent to DLL: " << config << std::endl;
    return true;
}

bool IsProcessRunning(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        return false;
    }
    CloseHandle(hProcess);
    return true;
}

void ReadMessagesFromSocket(std::atomic<bool>& stopFlag, DWORD targetPID) {
    char buffer[1024];
    while (!stopFlag) {
        if (g_socket == INVALID_SOCKET) {
            if (!IsProcessRunning(targetPID)) {
                std::cerr << "[PROGRAM] Target process is not running anymore. Exiting..." << std::endl;
                stopFlag = true;
                break;
            }
            Sleep(1000);
            continue;
        }

        int bytesRead = recv(g_socket, buffer, sizeof(buffer) - 1, 0);
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            std::string message(buffer);

            if (!message.empty() && message.back() == '\r') {
                message.pop_back();
            }
            if (!message.empty() && message.back() == '\n') {
                message.pop_back();
            }

            std::cout << "[LIBRARY] " << message << std::endl;

            if (message == "DLL disconnected") {
                std::cout << "[PROGRAM] Exiting..." << std::endl;
                stopFlag = true;
                break;
            }
        }
        else if (bytesRead == 0) {
            std::cerr << "[PROGRAM] Connection closed by server." << std::endl;
            closesocket(g_socket);
            g_socket = INVALID_SOCKET;
        }
        else {
            std::cerr << "[PROGRAM] Failed to read from socket: " << WSAGetLastError() << std::endl;
            closesocket(g_socket);
            g_socket = INVALID_SOCKET;
        }
    }

    if (g_socket != INVALID_SOCKET) {
        closesocket(g_socket);
        g_socket = INVALID_SOCKET;
    }
}

int main(int argc, char* argv[]) {
    ProgramArguments args;
    if (!ParseCommandLine(argc, argv, args)) {
        PrintUsage();
        return 1;
    }
    DWORD targetPID = 0;
    if (!args.processName.empty()) {
        targetPID = FindProcessByName(args.processName);
        if (targetPID == 0) {
            std::cerr << "[PROGRAM] Target process not found." << std::endl;
            return 1;
        }
    }
    else if (args.pid != -1) {
        targetPID = args.pid;
    }
    std::string dllPath("C:\\Users\\alien_aa\\source\\repos\\TRSPO\\winhooklib\\x64\\Debug\\winhooklib.dll");
    if (!InjectDLLIntoProcess(targetPID, dllPath)) {
        std::cerr << "[PROGRAM] Failed to inject DLL into target process." << std::endl;
        return 1;
    }
    std::cout << "[PROGRAM] DLL injected successfully into process with PID: " << targetPID << std::endl;
    if (!CreateSocketAndSendConfig(args)) {
        std::cerr << "[PROGRAM] Failed to establish communication with DLL." << std::endl;
        return 1;
    }
    std::cout << "[PROGRAM] Communication with DLL established successfully." << std::endl;
    std::atomic<bool> stopFlag(false);
    std::thread messageThread(ReadMessagesFromSocket, std::ref(stopFlag), targetPID);
    while (!stopFlag) {
        Sleep(100);
    }
    messageThread.join();
    if (g_socket != INVALID_SOCKET) {
        closesocket(g_socket);
        g_socket = INVALID_SOCKET;
    }
    WSACleanup();
    return 0;
}
