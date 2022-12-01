#include "injector.h"

bool IsCorrectTargetArchitecture(HANDLE hProc) {
	BOOL bTarget = FALSE;
	if (!IsWow64Process(hProc, &bTarget)) {
		printf("Can't confirm target process architecture: 0x%X\n", GetLastError());
		return false;
	}

	BOOL bHost = FALSE;
	IsWow64Process(GetCurrentProcess(), &bHost);

	return (bTarget == bHost);
}

DWORD getProcessId(char *processName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	char *tempName = new char[MAX_PATH];

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
			
            if (!strcmp((char *) entry.szExeFile, processName))
            {  
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        }
    }

    CloseHandle(snapshot);
    return 0;
}

void enableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);

    CloseHandle(hToken); 
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR pCmdLine, int nCmdShow) {

	int argc = 0;
	printf("%s\n", pCmdLine);
	
	for (int i = 0; i < __argc; i++) {
		printf("argv[%d] %s\n", i, __argv[i]);
	}

	char* dllPath = new char[MAX_PATH];
	char* funcName = nullptr;
	DWORD pid;
	printf("%d\n", __argc);
	if (__argc <= 1) {
		printf("Invalid Params\n");
		printf("Usage: dll_path [process_name [dllFuncName]]\n");
		return 1;
	}
	strcpy(dllPath, __argv[1]);

	switch(__argc) {
		case 4: 
		{
			funcName = new char[MAX_PATH];
			strcpy(funcName, __argv[3]);
		}
		case 3:
		{
			pid = getProcessId(__argv[2]);
			break;
		}
		case 2:
		{
			char *procName = new char[MAX_PATH];
			std::string pname;
			printf("Process Name:\n");
			scanf("%s\n", procName);
			// std::getline(std::cin, pname);

			// char* vIn = (char*) pname.c_str();
			pid = getProcessId(procName);
			delete procName;
			break;
		}
	}

	if (pid == 0) {
		printf("Process not found\n");
		return EXIT_FAILURE;
	}

	printf("Process pid: %d\n", pid);

	// enableDebugPrivilege();

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProc) {
		DWORD Err = GetLastError();
		printf("OpenProcess failed: 0x%X\n", Err);
		return EXIT_FAILURE;
	}

	if (!IsCorrectTargetArchitecture(hProc)) {
		printf("Invalid Process Architecture.\n");
		CloseHandle(hProc);
		return EXIT_FAILURE;
	}

	if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
		printf("Dll file doesn't exist. Error code: %d\n", GetLastError());
		CloseHandle(hProc);
		return EXIT_FAILURE;
	}

	std::ifstream fStream(dllPath, std::ios::binary | std::ios::ate);

	std::string dllPathStr(dllPath);
	std::string dllName = dllPathStr.substr(dllPathStr.find_last_of("/\\") + 1);
	
	printf("Gotten dllName %s\n", dllName.c_str());

	if (fStream.fail()) {
		printf("Opening the file failed: %X\n", (DWORD) fStream.rdstate());
		fStream.close();
		CloseHandle(hProc);
		return EXIT_FAILURE;
	}

	auto FileSize = fStream.tellg();
	if (FileSize < 0x1000) {
		printf("Filesize invalid.\n");
		fStream.close();
		CloseHandle(hProc);
		return EXIT_FAILURE;
	}

	BYTE * pSrcData = new BYTE[(UINT_PTR) FileSize];
	if (!pSrcData) {
		printf("Can't allocate dll file.\n");
		fStream.close();
		CloseHandle(hProc);
		return EXIT_FAILURE;
	}

	fStream.seekg(0, std::ios::beg);
	fStream.read((char*) pSrcData, FileSize);
	fStream.close();

	FARPROC fOffset = 0;

	if (funcName) {
		printf("dllPath %s\n", dllName.c_str());
		HMODULE hModule = LoadLibraryA(dllName.c_str());
		printf("funcName %s\n", funcName);
		printf("hModule %x \n", hModule);

		if (!hModule) {
			printf("Couldn't load library. Error code %d\n", GetLastError());
			delete[] pSrcData;

			CloseHandle(hProc);
			delete dllPath;
			return EXIT_FAILURE;
		}

		fOffset = (FARPROC) (GetProcAddress(hModule, funcName));

		#ifdef _WIN64
		fOffset = (FARPROC) ((long long) fOffset - (long long) hModule);
		#else
		fOffset = (FARPROC) ((long) fOffset - (long) hModule);
		#endif
		printf("foOffset %x proc %x\n", fOffset);
		FreeLibrary(hModule);
	}

	printf("Function offset: %x\n", fOffset);

	printf("Mapping...\n");
	if (!ManualMapDll(hProc, pSrcData, FileSize, fOffset)) {
		delete[] pSrcData;
		CloseHandle(hProc);
		printf("Error while mapping.\n");
		return EXIT_FAILURE;
	}

	delete[] pSrcData;
	delete dllPath;

	// LocalFree(argv);
	CloseHandle(hProc);
	printf("OK\n");
	return EXIT_SUCCESS;
}
