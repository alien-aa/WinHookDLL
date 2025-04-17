# WinHookDLL
WinHookDLL provides a program and DLL to intercept function calls and modify behavior in a target process, enabling function tracing and file hiding.

## Description

This project demonstrates techniques for injecting custom code into a target process to intercept function calls and modify their behavior. It features function call tracing and file hiding capabilities. The implementation uses function hooking and trampolines to maintain the target process's stability and functionality.

## Repository Structure

├── project1/

│   ├── monitor.cpp

│   ├── project1.sln

│   ├── project1.vcxproj

│   └── project1.vcxproj.filters

├── winhooklib/

│   ├── dllmain.cpp

│   ├── framework.h

│   ├── HookManager.cpp

│   ├── HookManager.h

│   ├── HookPatch.cpp

│   ├── HookPatch.h

│   ├── HookSource.cpp

│   ├── HookSource.h

│   ├── hook_body.asm

│   ├── pch.cpp

│   ├── pch.h

│   ├── winhooklib.sln

│   ├── winhooklib.vcxproj

│   └── winhooklib.vcxproj.filters

└── report.pdf

*   **`project1/`**: Contains the source code for `monitor.exe`, responsible for injecting the DLL into target processes.
    *   `monitor.cpp`: Main source file for the monitor application.
    *   `project1.sln`: Visual Studio solution file for the monitor project.
    *   `project1.vcxproj`: Visual Studio project file for the monitor project.
    *   `project1.vcxproj.filters`: Visual Studio filters file for the monitor project.
*   **`winhooklib/`**: Contains the source code for `winhooklib.dll`, which performs function hooking and file hiding.
    *   `dllmain.cpp`: DLL entry point.
    *   `framework.h`: Header file for the DLL project.
    *   `HookManager.cpp/HookManager.h`: Implements hook management, including loading target DLLs and locating function addresses.
    *   `HookPatch.cpp/HookPatch.h`: Implements function hooking using trampolines.
    *   `HookSource.cpp/HookSource.h`: Defines hook sources.
    *   `hook_body.asm`: Assembly code for hook implementation.
    *   `pch.cpp/pch.h`: Precompiled header files.
    *   `winhooklib.sln`: Visual Studio solution file for the DLL project.
    *   `winhooklib.vcxproj`: Visual Studio project file for the DLL project.
    *   `winhooklib.vcxproj.filters`: Visual Studio filters file for the DLL project.
*   **`report.pdf`**: PDF file containing a detailed report on the project's design, implementation details, and testing results.

## Features

*   **Function Call Tracing:** Logs calls to specified functions, displaying the function name and timestamp.
*   **File Hiding:** Modifies the behavior of `FindFirstFile`, `FindNextFile`, and `CreateFile` to hide a specified file.
*   **Trampoline Hooking:** Implements function hooking using trampolines to preserve original function behavior.
*   **Inter-Process Communication:** Uses sockets for communication between `monitor.exe` and `winhooklib.dll`.
*   **Dynamic DLL Injection:** Injects `winhooklib.dll` into a target process.

## Building and Running

### Prerequisites

*   Visual Studio (for building .sln projects)

### Building

1.  Clone the repository:

    ```
    git clone [repository URL]
    ```

2.  Open the solution files (`project1.sln` and `winhooklib.sln`) in Visual Studio.

3.  Build the projects in Visual Studio.

### Running

1.  Run `monitor.exe` with the appropriate command-line arguments to specify the target process and the functions to hook or files to hide.

    ```
    monitor.exe --pid <process_id> --hook <function_name>
    monitor.exe --pid <process_id> --hide <file_path>
    ```

2.  Observe the results: The monitor program will display function call logs or hide the specified file in the target process.
