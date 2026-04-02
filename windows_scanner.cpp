#ifdef _WIN32

#include <windows.h>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <iostream>
#include <fstream>
#include <string>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")

std::wofstream logFile;

void Log(const std::wstring& text) {
    std::wcout << text << std::endl;
    logFile << text << std::endl;
}

bool IsSigned(const std::wstring& filePath) {
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);

    return status == ERROR_SUCCESS;
}

void ScanMemory(HANDLE hProcess, DWORD pid) {
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* addr = 0;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {

        bool isExec =
            (mbi.Protect & PAGE_EXECUTE) ||
            (mbi.Protect & PAGE_EXECUTE_READ) ||
            (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
            (mbi.Protect & PAGE_EXECUTE_WRITECOPY);

        if (mbi.State == MEM_COMMIT && isExec) {

            if (mbi.Protect == PAGE_EXECUTE_READWRITE) {
                Log(L"[RWX] PID " + std::to_wstring(pid));
            }

            if (mbi.Type == MEM_PRIVATE) {
                Log(L"[PRIVATE EXEC] PID " + std::to_wstring(pid));
            }
        }

        addr += mbi.RegionSize;
    }
}

void ScanModules(HANDLE hProcess, DWORD pid) {
    HMODULE modules[1024];
    DWORD cbNeeded;

    if (EnumProcessModulesEx(hProcess, modules, sizeof(modules), &cbNeeded, LIST_MODULES_ALL)) {
        size_t count = cbNeeded / sizeof(HMODULE);

        for (size_t i = 0; i < count; i++) {
            wchar_t path[MAX_PATH];

            if (GetModuleFileNameExW(hProcess, modules[i], path, MAX_PATH)) {
                std::wstring dllPath = path;

                if (!IsSigned(dllPath)) {
                    Log(L"[UNSIGNED DLL] PID " + std::to_wstring(pid) + L": " + dllPath);
                }
            }
        }
    }
}

void ScanProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return;

    ScanModules(hProcess, pid);
    ScanMemory(hProcess, pid);

    CloseHandle(hProcess);
}

void RunWindowsScanner() {
    logFile.open("report.txt");

    DWORD processes[2048];
    DWORD cbNeeded;

    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        Log(L"Failed to enumerate processes.");
        return;
    }

    DWORD count = cbNeeded / sizeof(DWORD);

    for (DWORD i = 0; i < count; i++) {
        if (processes[i] != 0) {
            ScanProcess(processes[i]);
        }
    }

    logFile.close();
}

#endif