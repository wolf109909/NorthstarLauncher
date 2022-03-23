#pragma once
#include <string>
void LoadDllSignatures();
void InstallInitialHooks();

typedef void (*DllLoadCallbackFuncType)(HMODULE moduleAddress);
void AddDllLoadCallback(std::string dll, DllLoadCallbackFuncType callback);

void CallAllPendingDLLLoadCallbacks();