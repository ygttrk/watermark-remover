#include <iostream>
#include <windows.h>
#include <winternl.h>

#include <tlhelp32.h>
#include <shlobj.h> // SHChangeNotify

#include "PatternSearch.h";

typedef struct shellcodeStack {
//         [tag]                     [rbx+ Value]

    DWORD64 DosHeader;                  // 0x00
    DWORD64 ImportDescriptor;           // 0x08
    DWORD64 OriginalFuncAddr;           // 0x10
    DWORD64 FirstThunk;                 // 0x18
    DWORD64 OriginalFirstThunk;         // 0x20
    DWORD64 oldProtect;                 // 0x28
    DWORD64 VirtualProtectAddr;         // 0x30
    DWORD64 OGreturnAddr;               // 0x38
    DWORD64 hCreateFileW;               // 0x40
    DWORD64 hWriteFile;                 // 0x48
    DWORD64 pMSG;                       // 0x50
    DWORD64 hKernel32;                  // 0x58
    DWORD64 ExportedFuncNum;            // 0x60
    DWORD64 ExportedFunctionsTable;     // 0x68
    DWORD64 addressOfNamePointer;       // 0x70
    DWORD64 addressOfOrdinalTable;      // 0x78
    DWORD64 hGetProcAddress;            // 0x80
    DWORD64 firstReturnAddr;            // 0x88
    DWORD64 bytesWritten;               // 0x90
    DWORD64 AsciiValue;                 // 0x98
    //burdan sonrasý deneysel alan
    DWORD64 hLoadLibraryA;//0xA0
    //deneysel alan bitiþi string sahasý
    char USER32String[11];              // 0x100
    char GetMessageWString[12];         // 0x110 buraya faklý biþey gelebilir hooklanacak fonk bu ondan 0x20(32) bayt fazlasý var
    char VirtualProtectString[15];      // 0x130
    char KERNEL32String[13];            // 0x140
    char CreateFileWString[13];         // 0x150
    char WriteFileString[10];           // 0x160
    char LoadLibraryAString[12];        // 0x170
    char GetProcAddressString[15];      // 0x180
    char PipeNameString[1];             // 0x190
    //ekstralar
    byte isSyscallHook;                 // 0x1E0
    DWORD SyscallNum;                   // 0x1E2
                                        // 0x1E8
};


typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    ); 

BOOL isTestSigningEnabled() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        std::cerr << "[x]ntdll.dll!!!" << "\n";
        return -1;
    }

    PNtQuerySystemInformation NtQuerySystemInformation =
        (PNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) {
        std::cerr << "[x]NtQuerySystemInformation!!!" << "\n";
        FreeLibrary(hNtdll);
        return -1;
    }

    NTSTATUS status;
    ULONG requiredLen = 0;
    status = NtQuerySystemInformation(SystemCodeIntegrityInformation, nullptr, 0, &requiredLen);
    std::cout << "[x]Status: " << std::hex << status << "\n[x]requiredLen: " << requiredLen << "\n";

    void* buffer = malloc(requiredLen);
    unsigned long r8d = 0x08;
    //bufferin basina 8 koymayinca calismiyor sebebini bilmiyorum
    *(unsigned long*)buffer = r8d;
    status = NtQuerySystemInformation(SystemCodeIntegrityInformation, buffer, requiredLen, &requiredLen);

    if (!NT_SUCCESS(status)) {
        std::cout << "2.[x]Status: " << std::hex << status << "\n[x]requiredLen: " << requiredLen << "\n";
        return 0xFFFFFFFFFFFFFFFF;
    }

    unsigned char checkByte = *((unsigned char*)buffer + 0x04);
    if ((checkByte & 0x02) != 0)  // bit 1 (TESTSIGNING)
    {
        return 1;
    }
    if ((checkByte & 0x80) != 0)  // bit 7
    {
        return 1;
    }

    return 0;

    free(buffer);
    FreeLibrary(hNtdll);
}

DWORD FindProcessId(const std::wstring& processName) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry = { sizeof(entry) };

    if (Process32FirstW(snap, &entry)) {
        do {
            if (processName == entry.szExeFile) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return pid;
}


unsigned char* GetShell32Addr(DWORD pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Snapshot alýnamadý: " << GetLastError() << "\n";
        return 0x0000000000000000;
    }

    MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
    if (Module32First(snapshot, &me32)) {
        do {
            if (_wcsicmp(me32.szModule, L"SHELL32.dll") == 0) {
                std::wcout << L"Modül: " << me32.szModule
                    << L" | Base: " << me32.modBaseAddr
                    << L" | Size: " << me32.modBaseSize << L"\n";
                return me32.modBaseAddr;
            }
        } while (Module32Next(snapshot, &me32));
    }
    else {
        std::cerr << "Module32First baþarýsýz: " << GetLastError() << "\n";
    }

    CloseHandle(snapshot);

    return 0x0000000000000000;
}

//debug bayra aktif edilebilir belki byte deðiþtirmek için
BOOL patchIsSigningActiveFunc(unsigned long offset, bool testSigningFlag) {
    
    unsigned char* patch;
    size_t patchBuffer;
    if (testSigningFlag == true) {
        patchBuffer = 8;
        patch = (unsigned char*)malloc(8);
        *(unsigned long long*)patch = 0xc300000001c0c748;
        //patch = { 0x48, 0xc7 ,0xc0 ,0x01 ,0x00 ,0x00 ,0x00, 0xc3 }; //mov rax, 0x1; ret flagi yani acar
        
    }
    else {
        patchBuffer = 4;
        patch = (unsigned char*)malloc(4);
        *(unsigned long long*)patch = 0xc3c03148;
        //patch = { 0x48, 0x31, 0xc0, 0xc3 }; //xor rax,rax; ret yani kapatir
        
    }
 
    

    DWORD pid = FindProcessId(L"explorer.exe");
    if (pid == 0) {
        std::wcerr << L"Process not found.\n";
        return -1;
    }

    unsigned char* patchAddr = GetShell32Addr(pid);
    if (patchAddr == 0x0000000000000000) {
        return -1;
    }
    patchAddr += offset;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "OpenProcess failed: " << GetLastError() << "\n";
        return -1;
    }

    LPVOID targetAddress = (LPVOID)patchAddr; // örnek adres
    std::cout << "target address: " << targetAddress << "\n";

    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, targetAddress, patchBuffer, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "VirtualProtectEx failed: " << GetLastError() << "\n";
        return 0;
    }

    // Belleðe yaz
    if (!WriteProcessMemory(hProcess, targetAddress, patch, patchBuffer, nullptr)) {
        std::cerr << "WriteProcessMemory failed: " << GetLastError() << "\n";
        return 0;
    }
    else {
        std::cout << "Patch baþarýyla yazýldý.\n";
    }

    // Koruma geri alýnýr
    VirtualProtectEx(hProcess, targetAddress, patchBuffer, oldProtect, &oldProtect);

    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);

    CloseHandle(hProcess);

    return 1;
}

void changeTestSigning(bool testSigningFlag) {

    char patternStr[] = "48 83 ec 48 48 8b 05 ?? ?? ?? ?? 48 33 c4 48 89 44 24 30 41 b8 08 00 00 00 4c 8d 4c 24 28 48 8d 54 24 20 44 89 44 24 20 41 8d 48 5f 48 ff 15 ?? ?? ?? ?? 0f 1f 44 00 00 33 c9 85 c0 78 10 f6 44 24 24 02 75 07 f6 44 24 24 80 74 02 b1 01 8a c1 48 8b 4c 24 30 48 33 cc e8 ?? ?? ?? ?? ?? 83 c4 48 c3";

    char shell32path[] = "C:\\Windows\\System32\\Shell32.dll";
    HMODULE hModule = LoadLibraryA(shell32path);

    if (!hModule) {
        std::cerr << "Modül bulunamadý: " << shell32path << "\n";
        return;
    }

    // PE header üzerinden boyutu öðreniyoruz
    auto base = reinterpret_cast<BYTE*>(hModule);
    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
    DWORD baseSize = ntHeaders->OptionalHeader.SizeOfImage;

    size_t maxPattern = 3;

    unsigned long long* patternAddress = (unsigned long long*)patternSearch(base, baseSize, patternStr, maxPattern);

    for (size_t i = 0; i < maxPattern; i++) {
        if (*(patternAddress + i) == 0xCDCDCDCDCDCDCDCD) {
            break;
        }

        unsigned long long address = *(patternAddress + i);
        unsigned long long offset = address - (unsigned long long)hModule;
        std::cout << "address | offset: " << std::hex << address << " | " << offset << "\n";
        BOOL status;
        if (testSigningFlag == true) {
            status = patchIsSigningActiveFunc(offset, true);
        }
        else {
            status = patchIsSigningActiveFunc(offset, false);
        }
        
        if (status == 1) {
            printf("patch basarili");
        }
        else {
            std::cout << "ne yazik ki dansozeler burs alamali: " << status << "\n";
        }
    }

    free(patternAddress);
    FreeLibrary(hModule);
    return;
}


int main()
{
    BOOL testFlag = isTestSigningEnabled();
    if (testFlag == 0) {
        return 0;
        std::cout << "test zaten kapali bb\n" ;
    }
    else if (testFlag == 1){
        std::cout << "test yazisi acik kapanacak...\n";
        changeTestSigning(false);
    }


    /*if (testFlag == 0) {
        printf("test modu kapali ama yaziyi gormek ister misin (E/H): ");
        char response = getchar();
        switch (response)
        {
        case('E'): {
            changeTestSigning(true);
            break;
        }
        case('H'): {
            printf("yaziyi kapatmak icin reset at");
            break;
        }
        case('e'): {
            changeTestSigning(true);
            break;
        }
        case('h'): {
            printf("yaziyi kapatmak icin reset at");
            break;
        }
        default:
            printf("E yada H");
            break;
        }
    }
    else if (testFlag == 1) {
        printf("test modu acik yaziyi kapatmak icin D acmak icin E: ");
        char response = getchar();
        switch (response)
        {
        case('D'): {
            changeTestSigning(false);
            break;
        }
        case('E'): {
            changeTestSigning(true);
            break;
        }
        case('d'): {
            changeTestSigning(false);
            break;
        }
        case('e'): {
            changeTestSigning(true);
            break;
        }
        default:
            printf("(E/e) yada (H/h)");
            break;
        }
    }
    */


    return 0;
}
