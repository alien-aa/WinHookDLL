#include "pch.h"
#include "HookManager.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <thread>
#include <atomic>
#include <iostream>
#include <ctime>
#include <string>

#pragma comment(lib, "Ws2_32.lib")

std::atomic<SOCKET> g_socket(INVALID_SOCKET);
std::atomic<bool> g_running(true);

std::atomic<std::string*> func_name_ptr(nullptr);

bool CreateAndConnectSocket() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr); 
    serverAddr.sin_port = htons(12345);

    if (bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(listenSocket);
        WSACleanup();
        return false;
    }

    if (listen(listenSocket, 1) == SOCKET_ERROR) {
        closesocket(listenSocket);
        WSACleanup();
        return false;
    }

    SOCKET clientSocket = accept(listenSocket, NULL, NULL);
    if (clientSocket == INVALID_SOCKET) {
        closesocket(listenSocket);
        WSACleanup();
        return false;
    }

    closesocket(listenSocket);
    g_socket.store(clientSocket);
    return true;
}

bool SafeWriteToSocket(const std::string& message) {
    SOCKET currentSocket = g_socket.load();
    if (currentSocket == INVALID_SOCKET) {
        return false;
    }

    if (send(currentSocket, message.c_str(), message.size(), 0) == SOCKET_ERROR) {
        closesocket(currentSocket);
        g_socket.store(INVALID_SOCKET);
        return false;
    }

    return true;
}

extern "C" DWORD WINAPI log_function() {
    std::time_t now = std::time(nullptr);
    std::tm localTime;
    localtime_s(&localTime, &now);

    char timeBuffer[100];
    std::strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", &localTime);

    std::string* funcName = func_name_ptr.load();
    std::string message = "[" + std::string(timeBuffer) + "] Function called: '" + (funcName ? *funcName : "unknown") + "'\n";

    if (!SafeWriteToSocket(message)) {
        std::cerr << "[DLL] Failed to log function call." << std::endl;
    }

    return NULL;
}

extern "C" uint64_t orig_func_bytes = NULL;

void SocketCommunicationThread() {
    char buffer[1024];
    while (g_running) {
        SOCKET currentSocket = g_socket.load();

        if (currentSocket == INVALID_SOCKET) {
            if (!CreateAndConnectSocket()) {
                Sleep(500);
                continue;
            }
            currentSocket = g_socket.load();
        }

        int bytesRead = recv(currentSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            std::string message(buffer);

            if (!message.empty() && message.back() == '\r') {
                message.pop_back();
            }
            if (!message.empty() && message.back() == '\n') {
                message.pop_back();
            }

            if (message.find("hook:") == 0) {
                std::string funcName = message.substr(5);
                auto newFuncName = new std::string(funcName);
                func_name_ptr.store(newFuncName);
                orig_func_bytes = HookManager::get_instance().set_hook(funcName);
                if (!SafeWriteToSocket("Hook Mode\n")) {
                    std::cerr << "[DLL] Failed to confirm hook mode." << std::endl;
                }
            }
            else if (message.find("hide:") == 0) {
                std::string hidePath = message.substr(5);
                HookManager::get_instance().set_hide(hidePath);
                if (!SafeWriteToSocket("Hide Mode\n")) {
                    std::cerr << "[DLL] Failed to confirm hide mode." << std::endl;
                }
            }
        }
        else {
            closesocket(currentSocket);
            g_socket.store(INVALID_SOCKET);
        }

        Sleep(100);
    }

    delete func_name_ptr.exchange(nullptr);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        std::thread([] {
            if (!CreateAndConnectSocket()) {
                return;
            }
            SocketCommunicationThread();
            }).detach();
        break;
    }
    case DLL_PROCESS_DETACH:
        g_running = false;
        SOCKET currentSocket = g_socket.exchange(INVALID_SOCKET);
        if (currentSocket != INVALID_SOCKET) {
            HookManager::get_instance().clear();
            if (!SafeWriteToSocket("DLL disconnected\n")) {
                std::cerr << "[DLL] Failed to send disconnect message." << std::endl;
            }
            closesocket(currentSocket);
        }

        delete func_name_ptr.exchange(nullptr);
        WSACleanup();
        break;
    }
    return TRUE;
}