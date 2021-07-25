#pragma once
DWORD GetProcId(const char* procName);
HANDLE GetToken(DWORD pid);
BOOL SpawnSystemShell(HANDLE token, DWORD pid);