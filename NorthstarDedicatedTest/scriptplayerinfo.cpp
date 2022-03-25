#include "pch.h"
#include "scriptserverbrowser.h"
#include "squirrel.h"
#include "masterserver.h"
#include "gameutils.h"
#include "serverauthentication.h"
#include "hooks.h"
#include "anticheat.h"
//string function NSGetLocalPlayerUID(int index)
SQRESULT NSGetLocalPlayerUID(void* sqvm)
{
	ClientSq_pushstring(sqvm,g_LocalPlayerUserID, -1);
	return SQRESULT_NOTNULL;
}

void InitialiseScriptsPlayerInfo(HMODULE baseAddress)
{

	g_UISquirrelManager->AddFuncRegistration("int", "NSGetLocalPlayerUID", "", "", NSGetLocalPlayerUID);

}