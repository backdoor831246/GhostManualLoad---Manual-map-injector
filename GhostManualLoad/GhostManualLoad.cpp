// code author : github.com/backdoor831246
#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>

using namespace std;

// #define DISABLE_OUTPUT

#if defined(DISABLE_OUTPUT)
#define ILog(data, ...)
#else
#define ILog(text, ...) printf(text, __VA_ARGS__);
#endif

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
typedef BOOL(WINAPI* f_RtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, DWORD64);
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

typedef HMODULE(WINAPI* f_LoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* f_GetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* f_DLL_ENTRY_POINT)(HMODULE, DWORD, LPVOID);
typedef VOID(NTAPI* PIMAGE_TLS_CALLBACK)(PVOID, DWORD, PVOID);

struct MANUAL_MAPPING_DATA {
    LPVOID pbase;
    f_LoadLibraryA pLoadLibraryA;
    f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
    f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif
    HINSTANCE hMod;
    DWORD fdwReasonParam;
    LPVOID reservedParam;
    BOOL SEHSupport;
};

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

DWORD GetProcessIdByName(const wchar_t* processName) {
    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(hSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hSnap);
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return 0;
}

#pragma runtime_checks("", off)
#pragma optimize("", off)
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {
    if (!pData) {
        return;
    }

    BYTE* pBase = (BYTE*)pData->pbase;
    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)pBase;
    IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)(pBase + pDos->e_lfanew);
    IMAGE_OPTIONAL_HEADER* pOpt = &pNt->OptionalHeader;

    auto _LoadLibraryA = pData->pLoadLibraryA;
    auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
    auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif

    BYTE* LocationDelta = pBase - pOpt->ImageBase;
    if (LocationDelta) {
        if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
            auto* pRelocData = (IMAGE_BASE_RELOCATION*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

            while (pRelocData->VirtualAddress) {
                UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* pRelativeInfo = (WORD*)(pRelocData + 1);

                for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
                    if (RELOC_FLAG(*pRelativeInfo)) {
                        UINT_PTR* pPatch = (UINT_PTR*)(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
                        *pPatch += (UINT_PTR)LocationDelta;
                    }
                }
                pRelocData = (IMAGE_BASE_RELOCATION*)((BYTE*)pRelocData + pRelocData->SizeOfBlock);
            }
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* pImportDescr = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (pImportDescr->Name) {
            char* szMod = (char*)(pBase + pImportDescr->Name);
            HINSTANCE hDll = _LoadLibraryA(szMod);

            ULONG_PTR* pThunkRef = (ULONG_PTR*)(pBase + pImportDescr->OriginalFirstThunk);
            ULONG_PTR* pFuncRef = (ULONG_PTR*)(pBase + pImportDescr->FirstThunk);

            if (!pImportDescr->OriginalFirstThunk)
                pThunkRef = pFuncRef;

            for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, (char*)(*pThunkRef & 0xFFFF));
                }
                else {
                    auto* pImport = (IMAGE_IMPORT_BY_NAME*)(pBase + (*pThunkRef));
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
                }
            }
            ++pImportDescr;
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* pTLS = (IMAGE_TLS_DIRECTORY*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* pCallback = (PIMAGE_TLS_CALLBACK*)(pTLS->AddressOfCallBacks);
        for (; pCallback && *pCallback; ++pCallback)
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }

    BOOL ExceptionSupportFailed = FALSE;

#ifdef _WIN64
    // SEH only x64
    if (pData->SEHSupport) {
        auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excep.Size) {
            if (!_RtlAddFunctionTable(
                (IMAGE_RUNTIME_FUNCTION_ENTRY*)(pBase + excep.VirtualAddress),
                excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
                (DWORD64)pBase)) {
                ExceptionSupportFailed = TRUE;
            }
        }
    }
#endif

    if (pOpt->AddressOfEntryPoint) {
        auto _DllMain = (f_DLL_ENTRY_POINT)(pBase + pOpt->AddressOfEntryPoint);
        _DllMain((HMODULE)pBase, pData->fdwReasonParam, pData->reservedParam);
    }

    if (ExceptionSupportFailed)
        pData->hMod = (HINSTANCE)0x505050;
    else
        pData->hMod = (HINSTANCE)pBase;
}
#pragma optimize("", on)
#pragma runtime_checks("", on)

__declspec(noinline) void ShellcodeEnd() {}

bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize,
    bool ClearHeader = true,
    bool ClearNonNeededSections = true,
    bool AdjustProtections = true,
    bool SEHExceptionSupport = true) {

    IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
    IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
    IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
    BYTE* pTargetBase = nullptr;

    if (((IMAGE_DOS_HEADER*)pSrcData)->e_magic != 0x5A4D) {
        ILog("[!] Invalid file (not a valid PE)\n");
        return false;
    }

    pOldNtHeader = (IMAGE_NT_HEADERS*)(pSrcData + ((IMAGE_DOS_HEADER*)pSrcData)->e_lfanew);
    pOldOptHeader = &pOldNtHeader->OptionalHeader;
    pOldFileHeader = &pOldNtHeader->FileHeader;

    if (pOldFileHeader->Machine != CURRENT_ARCH) {
        ILog("[!] Invalid platform (x86/x64 mismatch)\n");
        return false;
    }

    ILog("[*] File validation passed\n");

    pTargetBase = (BYTE*)VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTargetBase) {
        ILog("[!] VirtualAllocEx failed: 0x%X\n", GetLastError());
        return false;
    }

    ILog("[*] Allocated memory at: 0x%p\n", pTargetBase);

    if (!WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr)) {
        ILog("[!] Failed to write headers: 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        return false;
    }

    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
    for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) {
            if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress,
                pSrcData + pSectionHeader->PointerToRawData,
                pSectionHeader->SizeOfRawData, nullptr)) {
                ILog("[!] Failed to write section %s: 0x%X\n", pSectionHeader->Name, GetLastError());
                VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
                return false;
            }
        }
    }

    ILog("[*] DLL sections written successfully\n");

    MANUAL_MAPPING_DATA data = { 0 };
    data.pbase = pTargetBase;
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
    data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else
    SEHExceptionSupport = false;
#endif
    data.fdwReasonParam = DLL_PROCESS_ATTACH;
    data.reservedParam = nullptr;
    data.SEHSupport = SEHExceptionSupport;

    BYTE* MappingDataAlloc = (BYTE*)VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!MappingDataAlloc) {
        ILog("[!] Failed to allocate mapping data: 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
        ILog("[!] Failed to write mapping data: 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        return false;
    }

    DWORD_PTR shellcodeSize = (DWORD_PTR)ShellcodeEnd - (DWORD_PTR)Shellcode;
    if (shellcodeSize > 0x1000) shellcodeSize = 0x1000;

    void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pShellcode) {
        ILog("[!] Failed to allocate shellcode: 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr)) {
        ILog("[!] Failed to write shellcode: 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
        return false;
    }

    ILog("[*] Shellcode written at: 0x%p\n", pShellcode);

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)pShellcode,
        MappingDataAlloc, 0, nullptr);
    if (!hThread) {
        ILog("[!] CreateRemoteThread failed: 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
        return false;
    }

    ILog("[*] Remote thread created, waiting for completion...\n");

    WaitForSingleObject(hThread, INFINITE);

    MANUAL_MAPPING_DATA data_checked = { 0 };
    ReadProcessMemory(hProc, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);

    CloseHandle(hThread);

    HINSTANCE hCheck = data_checked.hMod;

    if (!hCheck) {
        ILog("[!] Injection failed - hMod is NULL\n");
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
        return false;
    }

    if (hCheck == (HINSTANCE)0x505050) {
        ILog("[!] WARNING: SEH exception support failed\n");
    }

    ILog("[+] Injection successful DLL base: 0x%p\n", hCheck);

    BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024 * 20);
    if (emptyBuffer) {
        memset(emptyBuffer, 0, 1024 * 1024 * 20);

        if (ClearHeader) {
            WriteProcessMemory(hProc, pTargetBase, emptyBuffer, 0x1000, nullptr);
            ILog("[*] PE header cleared\n");
        }

        if (ClearNonNeededSections) {
            pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
            for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
                if (pSectionHeader->Misc.VirtualSize) {
                    if ((SEHExceptionSupport ? 0 : strcmp((char*)pSectionHeader->Name, ".pdata") == 0) ||
                        strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 ||
                        strcmp((char*)pSectionHeader->Name, ".reloc") == 0) {
                        WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress,
                            emptyBuffer, pSectionHeader->Misc.VirtualSize, nullptr);
                        ILog("[*] Section %s cleared\n", pSectionHeader->Name);
                    }
                }
            }
        }

        if (AdjustProtections) {
            pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
            for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
                if (pSectionHeader->Misc.VirtualSize) {
                    DWORD old = 0;
                    DWORD newP = PAGE_READONLY;

                    if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
                        newP = PAGE_READWRITE;
                    }
                    else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) {
                        newP = PAGE_EXECUTE_READ;
                    }

                    if (VirtualProtectEx(hProc, pTargetBase + pSectionHeader->VirtualAddress,
                        pSectionHeader->Misc.VirtualSize, newP, &old)) {
                        ILog("[*] Section %s protected as 0x%lX\n", (char*)pSectionHeader->Name, newP);
                    }
                }
            }
            DWORD old = 0;
            VirtualProtectEx(hProc, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);
        }

        WriteProcessMemory(hProc, pShellcode, emptyBuffer, 0x1000, nullptr);
        free(emptyBuffer);
    }

    VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
    VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);

    return true;
}

int main() {
    wstring dllPathW;
    string dllPathA;
    wstring processNameW;

    cout << "[*] DLL: ";
    getline(wcin, dllPathW);
    dllPathA = string(dllPathW.begin(), dllPathW.end());

    if (dllPathA.empty()) {
        cout << "[!] No path provided\n";
        return 1;
    }

    cout << "[*] process name: ";
    getline(wcin, processNameW);

    if (processNameW.empty()) {
        cout << "[!] No process name provided\n";
        return 1;
    }

    DWORD pid = GetProcessIdByName(processNameW.c_str());

    if (!pid) {
        wcout << L"[!] Target process " << processNameW << L" not found\n";
        return 1;
    }

    cout << "[*] PID: " << pid << "\n";


    ILog("[*] Target PID: %d\n", pid);

    HANDLE hFile = CreateFileA(dllPathA.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        ILog("[!] Cannot open DLL \n");
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        ILog("[!] Failed to get file size\n");
        return 1;
    }

    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        CloseHandle(hFile);
        ILog("[!] Memory allocation failed\n");
        return 1;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        ILog("[!] Failed to read DLL\n");
        return 1;
    }
    CloseHandle(hFile);

    ILog("[*] DLL loaded into memory (%d bytes)\n", fileSize);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        ILog("[!] Cannot open target process (Error: 0x%X)\n", GetLastError());
        ILog("[!] Try running as Administrator\n");
        return 1;
    }

    ILog("[*] Process handle obtained\n\n");

    bool result = ManualMapDll(hProc, buffer, fileSize, true, true, true, true);

    VirtualFree(buffer, 0, MEM_RELEASE);
    CloseHandle(hProc);

    if (result) {
        cout << "\n[+] Injection successfully\n";
    }
    else {
        cout << "\n[!] Injection failed\n";
    }

    cout << "\nPress any key to exit";
    cin.get();
    return result ? 0 : 1;
}