#include "pch.h"
#include "hooks.h"
#include "hookutils.h"
#include "sigscanning.h"
#include <string>
#include <wchar.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <Psapi.h>

typedef LPSTR (*GetCommandLineAType)();
LPSTR GetCommandLineAHook();

typedef HMODULE (*LoadLibraryExAType)(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
HMODULE LoadLibraryExAHook(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);

typedef HMODULE (*LoadLibraryAType)(LPCSTR lpLibFileName);
HMODULE LoadLibraryAHook(LPCSTR lpLibFileName);

typedef HMODULE (*LoadLibraryExWType)(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
HMODULE LoadLibraryExWHook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);

typedef HMODULE (*LoadLibraryWType)(LPCWSTR lpLibFileName);
HMODULE LoadLibraryWHook(LPCWSTR lpLibFileName);

GetCommandLineAType GetCommandLineAOriginal;
LoadLibraryExAType LoadLibraryExAOriginal;
LoadLibraryAType LoadLibraryAOriginal;
LoadLibraryExWType LoadLibraryExWOriginal;
LoadLibraryWType LoadLibraryWOriginal;


bool isDllSignatureLoaded = false;
std::vector<std::string> blacklistedDlls;


void InstallInitialHooks()
{
	if (MH_Initialize() != MH_OK)
		spdlog::error("MH_Initialize failed");

	HookEnabler hook;
	ENABLER_CREATEHOOK(hook, &GetCommandLineA, &GetCommandLineAHook, reinterpret_cast<LPVOID*>(&GetCommandLineAOriginal));
	ENABLER_CREATEHOOK(hook, &LoadLibraryExA, &LoadLibraryExAHook, reinterpret_cast<LPVOID*>(&LoadLibraryExAOriginal));
	ENABLER_CREATEHOOK(hook, &LoadLibraryA, &LoadLibraryAHook, reinterpret_cast<LPVOID*>(&LoadLibraryAOriginal));
	ENABLER_CREATEHOOK(hook, &LoadLibraryExW, &LoadLibraryExWHook, reinterpret_cast<LPVOID*>(&LoadLibraryExWOriginal));
	ENABLER_CREATEHOOK(hook, &LoadLibraryW, &LoadLibraryWHook, reinterpret_cast<LPVOID*>(&LoadLibraryWOriginal));
}

LPSTR GetCommandLineAHook()
{
	static char* cmdlineModified;
	static char* cmdlineOrg;

	if (cmdlineOrg == nullptr || cmdlineModified == nullptr)
	{
		cmdlineOrg = GetCommandLineAOriginal();
		bool isDedi = strstr(cmdlineOrg, "-dedicated"); // well, this one has to be a real argument
		bool ignoreStartupArgs = strstr(cmdlineOrg, "-nostartupargs");

		std::string args;
		std::ifstream cmdlineArgFile;

		// it looks like CommandLine() prioritizes parameters apprearing first, so we want the real commandline to take priority
		// not to mention that cmdlineOrg starts with the EXE path
		args.append(cmdlineOrg);
		args.append(" ");

		// append those from the file

		if (!ignoreStartupArgs)
		{

			cmdlineArgFile = std::ifstream(!isDedi ? "ns_startup_args.txt" : "ns_startup_args_dedi.txt");

			if (cmdlineArgFile)
			{
				std::stringstream argBuffer;
				argBuffer << cmdlineArgFile.rdbuf();
				cmdlineArgFile.close();

				// if some other command line option includes "-northstar" in the future then you have to refactor this check to check with
				// both either space after or ending with
				if (!isDedi && argBuffer.str().find("-northstar") != std::string::npos)
					MessageBoxA(
						NULL,
						"The \"-northstar\" command line option is NOT supposed to go into ns_startup_args.txt file!\n\nThis option is "
						"supposed to go into Origin/Steam game launch options, and then you are supposed to launch the original "
						"Titanfall2.exe "
						"rather than NorthstarLauncher.exe to make use of it.",
						"Northstar Warning", MB_ICONWARNING);

				args.append(argBuffer.str());
			}
		}

		auto len = args.length();
		cmdlineModified = new char[len + 1];
		if (!cmdlineModified)
		{
			spdlog::error("malloc failed for command line");
			return cmdlineOrg;
		}
		memcpy(cmdlineModified, args.c_str(), len + 1);

		spdlog::info("Command line: {}", cmdlineModified);
	}

	return cmdlineModified;
}

// dll load callback stuff
// this allows for code to register callbacks to be run as soon as a dll is loaded, mainly to allow for patches to be made on dll load
struct DllLoadCallback
{
	std::string dll;
	DllLoadCallbackFuncType callback;
	bool called;
};

std::vector<DllLoadCallback*> dllLoadCallbacks;

std::wstring StringToWString(const std::string& s)
{
	std::wstring temp(s.length(), L' ');
	std::copy(s.begin(), s.end(), temp.begin());
	return temp;
}


std::string WStringToString(const std::wstring& s)
{
	std::string temp(s.length(), ' ');
	std::copy(s.begin(), s.end(), temp.begin());
	return temp;
}
bool IsDllSignatureSafe(std::string dllname)
{	
	if (dllname.substr(dllname.find_last_of(".") + 1) == "dll") 
	{
		//spdlog::info("Attempting to sigscan:{}", dllname);
		void* ptr = FindSignature(dllname, "\x48\x8B\x05\x89\x0F\x00\x00\x81\xF9\x3B\x04\xF7\xC6", "xxxxx??xxxxxx");
		if (ptr != nullptr)
		{

			return false;
		}
		else
		{
			return true;
		}
	}
	else
	{
		return true;
	}
	
}

void LoadDllSignatures() 
{


	//blacklist
	blacklistedDlls.push_back("titan2hook_v1.3_[unknowncheats.me]_.dll");
	
	isDllSignatureLoaded = true;
}


void CheckDllBlacklist(LPCSTR lpLibFileName)
{
	//spdlog::info("checking Dll:{}", lpLibFileName);
	// Return true if Dll is not in blacklist
	if (isDllSignatureLoaded) 
	{

		std::string filepath = lpLibFileName;
		std::size_t dirpos = filepath.find_last_of("\\") + 1;
		std::string file = filepath.substr(dirpos, filepath.length() - dirpos);
		//auto findResult = std::find(blacklistedDlls.begin(), blacklistedDlls.end(), filepath);
		if (std::find(blacklistedDlls.begin(), blacklistedDlls.end(), file) != blacklistedDlls.end())
		{
			// Dangerous Dll name found
			//spdlog::info("Malicious Dll found:{}", filepath);
			MessageBox(NULL, TEXT("Go away.") , TEXT("Northstar has crashed!"), MB_OK | MB_ICONERROR);
			return;
		}
		else 
		{
			//spdlog::info("safe Dll found:{}", file);
			if (IsDllSignatureSafe(file))
			{
				return;


			}
			else 
			{
			
				MessageBox(NULL, TEXT("Go away. I said."), TEXT("Northstar has crashed!"), MB_OK | MB_ICONERROR );
				return;
			}
			
		}
	}


}


void CheckDllBlacklistW(LPCWSTR lpLibFileNameW)
{
	if (lpLibFileNameW != NULL) 
	{
		// Return true if Dll is not in blacklist
		std::string lpLibFileName = WStringToString(lpLibFileNameW);
		CheckDllBlacklist(lpLibFileName.c_str());
	}
}



void AddDllLoadCallback(std::string dll, DllLoadCallbackFuncType callback)
{
	DllLoadCallback* callbackStruct = new DllLoadCallback;
	callbackStruct->dll = dll;
	callbackStruct->callback = callback;
	callbackStruct->called = false;

	dllLoadCallbacks.push_back(callbackStruct);
}

void CallLoadLibraryACallbacks(LPCSTR lpLibFileName, HMODULE moduleAddress)
{
	for (auto& callbackStruct : dllLoadCallbacks)
	{
		if (!callbackStruct->called &&
			strstr(lpLibFileName + (strlen(lpLibFileName) - callbackStruct->dll.length()), callbackStruct->dll.c_str()) != nullptr)
		{
			callbackStruct->callback(moduleAddress);
			callbackStruct->called = true;
		}
	}
}

void CallLoadLibraryWCallbacks(LPCWSTR lpLibFileName, HMODULE moduleAddress)
{
	for (auto& callbackStruct : dllLoadCallbacks)
	{
		std::wstring wcharStrDll = std::wstring(callbackStruct->dll.begin(), callbackStruct->dll.end());
		const wchar_t* callbackDll = wcharStrDll.c_str();
		if (!callbackStruct->called && wcsstr(lpLibFileName + (wcslen(lpLibFileName) - wcharStrDll.length()), callbackDll) != nullptr)
		{
			callbackStruct->callback(moduleAddress);
			callbackStruct->called = true;
		}
	}
}

void CallAllPendingDLLLoadCallbacks()
{
	HMODULE hMods[1024];
	HANDLE hProcess = GetCurrentProcess();
	DWORD cbNeeded;
	unsigned int i;

	// Get a list of all the modules in this process.
	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			wchar_t szModName[MAX_PATH];

			// Get the full path to the module's file.
			if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
			{
				CallLoadLibraryWCallbacks(szModName, hMods[i]);
			}
		}
	}
}

HMODULE LoadLibraryExAHook(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	HMODULE moduleAddress = LoadLibraryExAOriginal(lpLibFileName, hFile, dwFlags);
	

	CheckDllBlacklist(lpLibFileName);

	if (moduleAddress)
	{
		CallLoadLibraryACallbacks(lpLibFileName, moduleAddress);
	}

	return moduleAddress;
}

HMODULE LoadLibraryAHook(LPCSTR lpLibFileName)
{
	HMODULE moduleAddress = LoadLibraryAOriginal(lpLibFileName);
	CheckDllBlacklist(lpLibFileName);

	if (moduleAddress)
	{
		CallLoadLibraryACallbacks(lpLibFileName, moduleAddress);
	}

	return moduleAddress;
}

HMODULE LoadLibraryExWHook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	HMODULE moduleAddress = LoadLibraryExWOriginal(lpLibFileName, hFile, dwFlags);
	CheckDllBlacklistW(lpLibFileName);

	if (moduleAddress)
	{
		CallLoadLibraryWCallbacks(lpLibFileName, moduleAddress);
	}

	return moduleAddress;
}

HMODULE LoadLibraryWHook(LPCWSTR lpLibFileName)
{
	HMODULE moduleAddress = LoadLibraryWOriginal(lpLibFileName);
	CheckDllBlacklistW(lpLibFileName);

	if (moduleAddress)
	{
		CallLoadLibraryWCallbacks(lpLibFileName, moduleAddress);
	}

	return moduleAddress;
}