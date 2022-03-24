#include "pch.h"
#include "hooks.h"
#include "hookutils.h"
#include "sigscanning.h"
#include <string>
#include "anticheat.h"
#include <wchar.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <Psapi.h>
#include "masterserver.h"


ClientAnticheatSystem g_ClientAnticheatSystem;

TempReadWrite::TempReadWrite(void* ptr)
{
	m_ptr = ptr;
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery(m_ptr, &mbi, sizeof(mbi));
	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect);
	m_origProtection = mbi.Protect;
}

TempReadWrite::~TempReadWrite()
{
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery(m_ptr, &mbi, sizeof(mbi));
	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, m_origProtection, &mbi.Protect);
}




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
void ClientAnticheatSystem::NoFindWindowHack(HMODULE baseAddress)
{
	unsigned seed = time(0);
	srand(seed);
	char ObfChar[3];
	int ObfuscateNum = 100 + rand() % 899;
	sprintf(ObfChar, "%d", ObfuscateNum);
	std::cout << ObfuscateNum << std::endl;
	char* ptr = ((char*)baseAddress + 0x607BD0);
	TempReadWrite rw(ptr);
	*(ptr + 14) = (char)ObfChar[0];
	*(ptr + 16) = (char)ObfChar[1];
	*(ptr + 18) = (char)ObfChar[2];
}
bool ClientAnticheatSystem::IsDllSignatureSafe(std::string dllname)
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

void ClientAnticheatSystem::LoadDllSignatures()
{
	//blacklist
	blacklistedDlls.push_back("titan2hook_v1.3_[unknowncheats.me]_.dll");

	isDllSignatureLoaded = true;
}


void ClientAnticheatSystem::CheckDllBlacklist(LPCSTR lpLibFileName)
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
			SendSelfReportToMasterServer((char*)file.c_str());
			//MessageBoxA(0, "Northstar has crashed! Error code: 0xFFFFFFFF", "Northstar has crashed!", MB_ICONERROR | MB_OK);
			//exit(0);
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
				SendSelfReportToMasterServer((char*)file.c_str());
				//MessageBoxA(0, "Northstar has crashed! Error code: 0xFFFFFFFE", "Northstar has crashed!", MB_ICONERROR | MB_OK);
				//exit(0);
				return;
			}

		}
	}


}


void ClientAnticheatSystem::CheckDllBlacklistW(LPCWSTR lpLibFileNameW)
{
	if (lpLibFileNameW != NULL)
	{
		// Return true if Dll is not in blacklist
		std::string lpLibFileName = WStringToString(lpLibFileNameW);
		CheckDllBlacklist(lpLibFileName.c_str());
	}
}

void ClientAnticheatSystem::FindMaliciousWindow() 
{
	if (ScanWindowProofAlreadyUploaded) 
	{
		return;
	}
	LPCSTR title = "ttf2 [steam]";
	HWND window = FindWindowA(NULL, title);
	if (window == NULL) 
	{
		// Malicious window title not found
		return;
	}
	else 
	{
		char* info = (char*)"ttf2_[unknowncheats.me]_.exe";
		SendSelfReportToMasterServer(info);
		//MessageBoxA(0, "Northstar has crashed! Error code: 0xFFFFFFFD", "Northstar has crashed!", MB_ICONERROR | MB_OK);
		//exit(0);
		ScanWindowProofAlreadyUploaded = true;
		return;
	}
	
}

void ClientAnticheatSystem::SendSelfReportToMasterServer(char* info)
{
	
	g_MasterServerManager->SendCheatingProof(info);

	return;
}
void ClientAnticheatSystem::InitWindowListenerThread()
{

	std::thread WindowListenerThread([this]
		{
			while (true)
			{
				FindMaliciousWindow();
				std::this_thread::sleep_for(std::chrono::milliseconds(10000));
			}
		});

	WindowListenerThread.detach();
}