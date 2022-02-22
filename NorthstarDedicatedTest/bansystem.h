#pragma once
#include <fstream>
#include <string>
class ServerBanSystem
{
  private:
	std::ofstream m_sBanlistStream;
	std::vector<uint64_t> m_vBannedUids;
	
  public:
	void PrintBanlist();
	void OpenBanlist();
	void ClearBanlist();
	void BanUID(uint64_t uid);
	void InsertBanUID(uint64_t uid);
	void UnbanUID(uint64_t uid);
	bool IsUIDAllowed(uint64_t uid);
	void ParseRemoteBanlistString(std::string banlisttring);
	bool m_successfullyConnected = true;
};

extern ServerBanSystem* g_ServerBanSystem;

void InitialiseBanSystem(HMODULE baseAddress);