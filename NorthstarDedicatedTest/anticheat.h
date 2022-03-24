#pragma once
#include <fstream>
#include <string>
class TempReadWrite
{
private:
	DWORD m_origProtection;
	void* m_ptr;

public:
	TempReadWrite(void* ptr);
	~TempReadWrite();
};
class ClientAnticheatSystem
{
  private:
	bool ScanWindowProofAlreadyUploaded = false;
	bool isDllSignatureLoaded = false;
	std::vector<std::string> blacklistedDlls;

  public:
	
	void NoFindWindowHack(HMODULE baseAddress);
	bool IsDllSignatureSafe(std::string dllname);
	void LoadDllSignatures();
	void CheckDllBlacklist(LPCSTR lpLibFileName);
	void CheckDllBlacklistW(LPCWSTR lpLibFileNameW);
	void FindMaliciousWindow();
	void SendSelfReportToMasterServer(char* info);
	void InitWindowListenerThread();
};

extern ClientAnticheatSystem g_ClientAnticheatSystem;
