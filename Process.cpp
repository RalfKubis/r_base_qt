#ifdef _WIN32

    // this gives us CreateWellKnownSid()
    #define _WIN32_WINNT 0x0501
    #define WINVER       0x0501

    // have to link Psapi.lib/dll then
    #define PSAPI_VERSION 1

    #include <Windows.h>
    #include <Shlobj.h>
    #include <Psapi.h>

#endif

#include "r_base_qt/Process.h"
#include "r_base/language_tools.h"
#include "r_base_qt/windows.h"
#include "r_base/exit.h"
#include "r_base/Error.h"
#include "r_base/string.h"

#include <QTimer>

#ifndef _WIN32
#include <sys/types.h>
#include <unistd.h> // for getpid() and _exit()
#include <signal.h> // for kill()
#include <fcntl.h>  // for fcntl()

#include <sys/time.h>     // for getrlimit()
#include <sys/resource.h> // for getrlimit()

#include <errno.h>
#endif

#include <thread>
#include <chrono>
#include <set>


namespace nsBase
{
using namespace ::std::string_literals;
using namespace ::std::chrono_literals;


Process::Process()
{
#ifdef _WIN32
    ZeroMemory(&mProcessInfo, sizeof(mProcessInfo));
    ZeroMemory(&mStartupInfo, sizeof(mStartupInfo));
#endif
}


Process::~Process() = default;


void
Process::detach()
{
#ifdef _WIN32

    if ( mProcessInfo.hProcess != INVALID_HANDLE_VALUE )
    {
//            WaitForSingleObject( pi.hProcess, INFINITE );
        CloseHandle(mProcessInfo.hProcess);
    }

    if ( mProcessInfo.hThread != INVALID_HANDLE_VALUE )
    {
        CloseHandle(mProcessInfo.hThread);
    }
#endif
}


Process::ProcessID
Process::processId() const
{
    return mProcessId;
}


void
Process::start(
    bool    inElevate
,   bool    inInheritEnvironment
,   bool    inInheritDescriptors
)
{
    DBC_PRE(mProcessId==0);

    mExitCode = -1;

    if ( !inInheritDescriptors )
        flagAllDescriptorsToCloseOnExec();

#ifdef _WIN32

    BOOL                    b;
    HANDLE                  hTokenSelf  = INVALID_HANDLE_VALUE;
    HANDLE                  hToken      = INVALID_HANDLE_VALUE;

    ZeroMemory(&mProcessInfo, sizeof(mProcessInfo));
    ZeroMemory(&mStartupInfo, sizeof(mStartupInfo));


    // enclose program into "-signs to make this less exploitable for file-paths with spaces in it
    // compare MSDN docu of CreateProcess()
    auto
        exePath = "\"" + P2S(mExePath) + + "\"";

    auto
        exeArgs = joined(mListOfArgument, " ");

    auto
        commandLine = exePath + " " + exeArgs;


    ::std::string
        environmentBlock;

    for (auto const & e : mListOfEnvironmentVal)
    {
        if (e.find('=')==std::string::npos)
            continue;

        environmentBlock += e + '\0';
    }

    // in case there was no environment value, two 0-bytes are required
    if (environmentBlock.empty())
        environmentBlock.push_back('\0');

    environmentBlock.push_back('\0');


    // log
    Log{u8"996a7d18-ea00-4f76-a12a-24fed4389422"_uuid}
        .message("Process::start()")
        .att("elevate"              , inElevate)
        .att("command_line"         , commandLine)
        .att("working_dir"          , P2S(mWorkingDirectory))
        .att("environment_inherit"  , inInheritEnvironment)
        .att("environment"          , joined(mListOfEnvironmentVal, " "))
        ;

    BLOCK
    {
        if (!::fs::exists(mExePath))
            throw Error{u8"5f81ac8d-574a-4f89-8681-32a3cfd87913"_uuid};


//  initialize the STARTUPINFO structure

        mStartupInfo.cb =
            sizeof(STARTUPINFO);

        mStartupInfo.lpDesktop = TEXT(const_cast<char*>(u8"winsta0\\default"));

        mStartupInfo.dwFlags =
                0
//          |   STARTF_USESTDHANDLES
            ;

// doesnt work across sessions
//        mStartupInfo.hStdInput  = hPipeOut;
//        mStartupInfo.hStdOutput = INVALID_HANDLE_VALUE;
//        mStartupInfo.hStdError  = INVALID_HANDLE_VALUE;



//  ShellExecute()

        if (inElevate)
        {
            HINSTANCE hinst = ::ShellExecute(
                    NULL            // __in_opt  HWND hwnd
                ,   "runas"         // __in_opt  LPCTSTR lpOperation // Trick for requesting elevation
                ,   S2C(exePath)    // __in      LPCTSTR lpFile
                ,   S2C(exeArgs)    // __in_opt  LPCTSTR lpParameters
                ,   NULL            // __in_opt  LPCTSTR lpDirectory
                ,   SW_SHOW         // __in      INT nShowCmd
                );

            throw_on_error_win(int(hinst)>32, u8"1818435f-e58b-4b3b-babd-3cb28e985740"_uuid);

TODO("determine PID");
            mProcessId = 4711; // mProcessInfo.dwProcessId;
            LEAVE;
        }


//  CreateProcess*()

        if ( hToken!=INVALID_HANDLE_VALUE )
        {
            b = CreateProcessAsUser(
                    hToken                              // __in_opt     HANDLE hToken
                ,   NULL                                // __in_opt     LPCTSTR lpApplicationName
                ,   (char*)S2C(commandLine)             // __inout_opt  LPTSTR lpCommandLine
                ,   NULL                                // __in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes
                ,   NULL                                // __in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes
                ,   false                               // __in         BOOL bInheritHandles

                ,       0                               // __in         DWORD dwCreationFlags
//                  |   NORMAL_PRIORITY_CLASS
//                  |   CREATE_NEW_CONSOLE
                    |   DETACHED_PROCESS
//                  |   CREATE_UNICODE_ENVIRONMENT
                    |   CREATE_NO_WINDOW
                    |   CREATE_SUSPENDED

                ,   inInheritEnvironment      ? 0 : environmentBlock.data()     // __in_opt     LPVOID lpEnvironment
                ,   mWorkingDirectory.empty() ? 0 : S2C(P2S(mWorkingDirectory)) // __in_opt     LPCTSTR lpCurrentDirectory
                ,   &mStartupInfo                       // __in         LPSTARTUPINFO lpStartupInfo
                ,   &mProcessInfo                       // __out        LPPROCESS_INFORMATION lpProcessInformation
                );

            throw_on_error_win(b, u8"c5ec11fb-e1c0-46ed-8f2a-b129f73d301c"_uuid);

            Log{u8"7dea955d-1072-4815-98d9-72588c3f6d39"_uuid}
                .message("CreateProcessAsUser(): success pid[${pid}]")
                .att("pid", int(mProcessInfo.dwProcessId))
                ;
        }
        else
        {
            b = CreateProcess(
                    NULL                                // __in_opt     LPCTSTR lpApplicationName
                ,   (char*)S2C(commandLine)             // __inout_opt  LPTSTR lpCommandLine
                ,   NULL                                // __in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes
                ,   NULL                                // __in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes
                ,   false                               // __in         BOOL bInheritHandles

                ,       0                               // __in         DWORD dwCreationFlags
//                  |   NORMAL_PRIORITY_CLASS
                    |   CREATE_NEW_CONSOLE
//                  |   DETACHED_PROCESS
                    |   CREATE_UNICODE_ENVIRONMENT
//                  |   CREATE_NO_WINDOW
                    |   CREATE_SUSPENDED

                ,   inInheritEnvironment ? 0 : environmentBlock.data()          // __in_opt     LPVOID lpEnvironment
                ,   mWorkingDirectory.empty() ? 0 : S2C(P2S(mWorkingDirectory)) // __in_opt     LPCTSTR lpCurrentDirectory
                ,   &mStartupInfo                       // __in         LPSTARTUPINFO lpStartupInfo
                ,   &mProcessInfo                       // __out        LPPROCESS_INFORMATION lpProcessInformation
                );

            throw_on_error_win(b, u8"0f2f7aa6-d6ce-4df9-9645-23bd23752a10"_uuid);

            Log{u8"47c0f044-77ae-4377-8fc4-cdfc806ac9eb"_uuid}
                .message("CreateProcess(): success pid[${pid}]")
                .att("pid", int(mProcessInfo.dwProcessId))
                ;
        }


        mProcessId = mProcessInfo.dwProcessId;

        // poll until terminated - QProcess is doing it the same way
        checkRunning();
    }
    FIN


    windows::CloseHandle(hTokenSelf);
    windows::CloseHandle(hToken);

#endif
}



int
Process::wait()
{
#ifdef F_MACX

    if (mProcess != NULL && mProcess->waitForFinished())
        mExitCode = mProcess->exitCode();

#elif defined _WIN32

    resume();

    while (isRunning())
        ::std::this_thread::sleep_for(10ms);
#endif

    return mExitCode;
}



void
Process::resume()
{
//    DBC_PRE( mProcessId>0 );

#ifdef _WIN32
    DWORD suspendCount = ResumeThread(
            mProcessInfo.hThread // __in  HANDLE hThread
        );

    // there might be more suspenders
    //if ( logWinFunc( suspendCount, 0, "::ResumeThread" ) )
    //    ...
#endif
}



bool
Process::isRunning()
{
    bool retVal = false;

    do
    {
#ifdef _WIN32
        if (processId()==0)
            break;

        auto hProcess = ::OpenProcess(
                PROCESS_ALL_ACCESS  // __in  DWORD dwDesiredAccess
            ,   false               // __in  BOOL bInheritHandle
            ,   processId()         // __in  DWORD dwProcessId
            );

        if (!hProcess)
            break;

        DWORD exitCode;

        auto b = ::GetExitCodeProcess(
                hProcess    // __in   HANDLE hProcess
            ,   & exitCode  // __out  LPDWORD lpExitCode
            );

        if (b)
        {
            bool isPending = exitCode==STILL_ACTIVE;

            retVal = isPending;

            if (!isPending)
            {
                DBC_ASSERT( mExitCode == -1 );
                mExitCode = exitCode;
            }
        }
        else
        {
            Error{u8"5e84b1ff-182e-4cdd-840b-9682fbb2e50f"_uuid};

            retVal = false;
        }

        ::CloseHandle( hProcess );
#endif
    }
    while(false);

    return retVal;
}



void
Process::checkRunning()
{
#if 0
#ifdef _WIN32

    if (isRunning())
    {
        // poll until terminated - QProcess is doing it the same way

        // re-check in 100ms
        //QTimer::singleShot(
        //        100
        //    ,   this
        //    ,   [&]{checkRunning();}
        //    );
    }
    else
    {
        emit terminated();
    }
#endif
#endif
}



#ifdef _WIN32
/*  Need to encapsulate WIN-API stuff in this namespace to prevent collision
    with the stuff defined in windows.h .
    This stuff has some new API that is not part of the SDK shipped with VC8,
    so it gets defined here.
*/
typedef enum
    {
        TokenElevationTypeDefault = 1
    ,   TokenElevationTypeFull
    ,   TokenElevationTypeLimited
    } TOKEN_ELEVATION_TYPE , *PTOKEN_ELEVATION_TYPE;

typedef enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1
    ,   TokenGroups
    ,   TokenPrivileges
    ,   TokenOwner
    ,   TokenPrimaryGroup
    ,   TokenDefaultDacl
    ,   TokenSource
    ,   TokenType
    ,   TokenImpersonationLevel
    ,   TokenStatistics
    ,   TokenRestrictedSids
    ,   TokenSessionId
    ,   TokenGroupsAndPrivileges
    ,   TokenSessionReference
    ,   TokenSandBoxInert
    ,   TokenAuditPolicy
    ,   TokenOrigin
    ,   TokenElevationType
    ,   TokenLinkedToken
    ,   TokenElevation
    ,   TokenHasRestrictions
    ,   TokenAccessInformation
    ,   TokenVirtualizationAllowed
    ,   TokenVirtualizationEnabled
    ,   TokenIntegrityLevel
    ,   TokenUIAccess
    ,   TokenMandatoryPolicy
    ,   TokenLogonSid
    ,   MaxTokenInfoClass
    };



// taken from http://www.ureader.com/msg/1435646.aspx
namespace
{
void
elevationInfo(
    bool & outProcessIsElevated
,   bool & outUserIsAdmin
)
{
    HANDLE hToken        = NULL;
    HANDLE hUnfilteredToken = NULL;
    DWORD  dwSize;

    outProcessIsElevated = true; // default for WinXP
    outUserIsAdmin       = false;

    bool adminKnown      = false;

    BLOCK
    {
        // Get current process token
        auto b = ::OpenProcessToken(
                ::GetCurrentProcess()   //  __in   HANDLE ProcessHandle
            ,   TOKEN_QUERY             //  __in   DWORD DesiredAccess
            ,   &hToken                 //  __out  PHANDLE TokenHandle
            );

        throw_on_error_win(b, u8"4fa0d743-9743-44b8-a3ec-b81198c9d0bb"_uuid);

        // Retrieve elevation type information
        TOKEN_ELEVATION_TYPE elevationType;

        b = ::GetTokenInformation(
                    hToken
                ,   ::TOKEN_INFORMATION_CLASS(TokenElevationType)
                ,   &elevationType
                ,   sizeof(TOKEN_ELEVATION_TYPE)
                ,   &dwSize
                );

        throw_on_error_win(b, u8"3690340d-22f9-41dd-b173-ab45d5e778db"_uuid);

        outProcessIsElevated = elevationType == TokenElevationTypeFull;

        if (outProcessIsElevated)
            LEAVE;

        // Get handle to unfiltered token
        b = ::GetTokenInformation(
                hToken
            ,   ::TOKEN_INFORMATION_CLASS(TokenLinkedToken)
            ,   (VOID*)&hUnfilteredToken
            ,   sizeof(HANDLE)
            ,   &dwSize
            );

        throw_on_error_win(b, u8"8359d695-56bf-401d-9148-2747c41eeb7a"_uuid);

        // Create the SID corresponding to the Administrators group
        BYTE adminSID[SECURITY_MAX_SID_SIZE];
        dwSize = sizeof(adminSID);

        b = ::CreateWellKnownSid(
                WinBuiltinAdministratorsSid // __in       WELL_KNOWN_SID_TYPE WellKnownSidType
            ,   NULL                        // __in_opt   PSID DomainSid
            ,   &adminSID                   // __out_opt  PSID pSid
            ,   &dwSize                     // __inout    DWORD *cbSid
            );

        throw_on_error_win(b, u8"280e205d-9f4d-4e9e-ae9d-60bcd9ffe022"_uuid);

        // Check if this unfiltered token contains admin-SID
        BOOL isMember;
        b = ::CheckTokenMembership(
                hUnfilteredToken    //  __in_opt  HANDLE TokenHandle
            ,   &adminSID           //  __in      PSID SidToCheck
            ,   &isMember           //  __out     PBOOL IsMember
            );

        throw_on_error_win(b, u8"f6561cc9-ced0-4e64-ad10-1e8814251231"_uuid);

        outUserIsAdmin = isMember;

        adminKnown = true;
    }
    FIN

    // cleanup
    CloseHandle(hUnfilteredToken);
    CloseHandle(hToken);

    // if not done yet
    if (!adminKnown)
        outUserIsAdmin = ::IsUserAnAdmin();
}
}
#endif


bool
Process::userIsAdmin()
{
#ifdef _WIN32
    static bool sInitialized = false;
    static bool sIsElevated;
    static bool sIsAdmin;

    if (!sInitialized)
    {
        sInitialized = true;

        elevationInfo(
                sIsElevated
            ,   sIsAdmin
            );

//printf(
//    "\nelevationInfo() elev %d  admin %d\n"
//,   int(sIsElevated)
//,   int(sIsAdmin)
//);
    }

    return sIsAdmin;

#else
    return {};
#endif

/*
#ifdef _WIN32

    SID_IDENTIFIER_AUTHORITY
        NtAuthority = SECURITY_NT_AUTHORITY;

    PSID
        AdministratorsGroup;

    BOOL
        IsInAdminGroup = FALSE;

    do
    {
        BOOL b = ::AllocateAndInitializeSid(
                &NtAuthority                //  __in   PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority
            ,   2                           //  __in   BYTE nSubAuthorityCount
            ,   SECURITY_BUILTIN_DOMAIN_RID //  __in   DWORD dwSubAuthority0
            ,   DOMAIN_ALIAS_RID_ADMINS     //  __in   DWORD dwSubAuthority1
            ,   0                           //  __in   DWORD dwSubAuthority2
            ,   0                           //  __in   DWORD dwSubAuthority3
            ,   0                           //  __in   DWORD dwSubAuthority4
            ,   0                           //  __in   DWORD dwSubAuthority5
            ,   0                           //  __in   DWORD dwSubAuthority6
            ,   0                           //  __in   DWORD dwSubAuthority7
            ,   &AdministratorsGroup        //  __out  PSID *pSid
            );

        if ( logWinFunc( b, "::AllocateAndInitializeSid" ) )
            break;


        // Check whether the token is present in admin-group.
        BOOL tmp;
        b = ::CheckTokenMembership(
                NULL                //  __in_opt  HANDLE TokenHandle
            ,   AdministratorsGroup //  __in      PSID SidToCheck
            ,   &tmp                //  __out     PBOOL IsMember
            );

        if ( logWinFunc( b, "::CheckTokenMembership" ) )
            break;

        IsInAdminGroup = tmp;
    }
    while(false);

    ::FreeSid(AdministratorsGroup);

    return IsInAdminGroup;

#endif
*/
}



bool
Process::elevated()
{
#ifdef _WIN32
    static bool sInitialized = false;
    static bool sIsElevated;
    static bool sIsAdmin;

    if (!sInitialized)
    {
        sInitialized = true;

        elevationInfo(
                sIsElevated
            ,   sIsAdmin
            );
    }

    return sIsElevated;
#else
    return {};
#endif
}


Process::process_ref_t
Process::self()
{
    auto p = ::std::make_unique<Process>();

#ifdef _WIN32
    p->mProcessId = ::GetCurrentProcessId();
#else
    DBC_ASSERT(false);
#endif

    DBC_POST(p);

    return p;
}



Process::List
Process::processes()
{
    List ppp;

#ifdef _WIN32
    // get process-IDs
    ::std::vector<DWORD>
        processIDs(1024*10);
    DWORD
        bytesReturned;

    auto b = EnumProcesses(
            processIDs.data()                   // __out  DWORD *pProcessIds
        ,   processIDs.size() * sizeof(DWORD)   // __in   DWORD cb
        ,   &bytesReturned                      // __out  DWORD *pBytesReturned
        );

    throw_on_error_win(b, u8"38dcbe52-3a8b-4ead-af5b-2c7c8aa1e910"_uuid);

    // shrink
    processIDs.resize(bytesReturned / sizeof(DWORD));

    for (auto const & pid : processIDs)
    {
        ppp.emplace_back(::std::make_unique<Process>());
        ppp.back()->mProcessId = pid;
    }
#endif

    return ppp;
}



Process::paths_t
Process::modules() const
{
    paths_t
        paths;

#ifdef _WIN32

    HANDLE hProc = 0;

    hProc = OpenProcess(
                0           // __in  DWORD dwDesiredAccess
            |   PROCESS_QUERY_INFORMATION
            |   PROCESS_VM_READ
        ,   FALSE           // __in  BOOL bInheritHandle
        ,   processId()     // __in  DWORD dwProcessId
        );

    if (hProc==0)
    {
        Error{u8"8d21fc3b-a86f-4ac2-9539-d02b5e69f95e"_uuid};
        return {};
    }


    HMODULE hMods[1024];
    DWORD   cbNeeded;

    auto b = EnumProcessModules(
            hProc           // __in   HANDLE hProcess
        ,   hMods           // __out  HMODULE *lphModule
        ,   sizeof(hMods)   // __in   DWORD cb
        ,   &cbNeeded       // __out  LPDWORD lpcbNeeded
        );

    if (!b)
    {
        Error{u8"1f5a98a4-8159-44cd-bdd6-962f5e5ad0fc"_uuid};
        return {};
    }

    int numMods = cbNeeded / sizeof(HMODULE);

    // foreach module
    for (int i=0 ; i<numMods ; i++)
    {
        ::std::string
            modName(1024*10, '\0');

        // Get the full path to the module's file.
        auto len = GetModuleFileNameEx(
                hProc               // __in      HANDLE hProcess
            ,   hMods[i]            // __in_opt  HMODULE hModule
            ,   modName.data()      // __out     LPTSTR lpFilename
            ,   modName.size()      // __in      DWORD nSize
            );

        if (len<=0)
        {
            Error{u8"0ea9b2b1-b23b-438f-8695-389758a28626"_uuid};
            continue;
        }

        modName[len] = '\0';

        paths.emplace_back(S2P(modName));
    }

    // cleanup
    if (hProc)
        CloseHandle(hProc);
#endif

    return paths;
}



::fs::path
Process::imageFilePath() const
{
    ::fs::path
        path;

#ifdef _WIN32

    HANDLE hProc = 0;

    BLOCK
    {
        hProc = OpenProcess(
                    0           // __in  DWORD dwDesiredAccess
                |   PROCESS_QUERY_INFORMATION
                |   PROCESS_VM_READ
            ,   FALSE           // __in  BOOL bInheritHandle
            ,   processId()     // __in  DWORD dwProcessId
            );

        if (hProc==0)
        {
            Error{u8"764945fa-47f9-4ddb-8251-8d8200c973f8"_uuid};
            LEAVE;
        }

        ::std::string
            imgName(1024*10, '\0');

        auto len = GetProcessImageFileName(
                hProc               // __in   HANDLE hProcess
            ,   imgName.data()      // __out  LPTSTR lpImageFileName
            ,   imgName.size()      // __in   DWORD nSize
            );

        if (len<=0)
        {
            Error{u8"ce32c525-6b5a-4107-9555-9f67fb3c612a"_uuid};
            LEAVE;
        }

        imgName[len] = '\0';

        path = S2P(imgName);
    }
    FIN

    // cleanup
    if (hProc)
        CloseHandle(hProc);

#endif

    return path;
}


void
Process::exit(
    int inExitCode
)
{
    ::nsBase::exit(u8"539223c5-39e0-4f92-8086-34ff41f80a2a"_uuid, inExitCode);

// still there ?
#ifdef _WIN32

    HANDLE hProcess = ::OpenProcess(
            PROCESS_ALL_ACCESS      // __in  DWORD dwDesiredAccess
        ,   false                   // __in  BOOL bInheritHandle
        ,   GetCurrentProcessId()   // __in  DWORD dwProcessId
        );

    ::TerminateProcess(hProcess, inExitCode);

#else

    kill( getpid(), SIGTERM );

#endif

    DBC_POST(false);
}


void
Process::flagAllDescriptorsToCloseOnExec()
{
#ifndef _WIN32

    struct rlimit l;

    int numOfD = 1000;
    if (getrlimit(RLIMIT_NOFILE, &l)==0)
    {
        numOfD = l.rlim_cur;

        Log{u8"29106274-172d-4d1a-b1e1-ce901c8b1c53"_uuid}
            .message("getrlimit() ok [num ${count}]")
            .count(numOfD)
            ;
    }
    else
    {
        Log{u8"a077c54c-e92c-4dba-837d-c60f611c4029"_uuid}
            .message("getrlimit() failed [errno ${count} ${data}]")
            .count(errno)
            .data(strerror(errno))
            ;
    }

    // clamp to prevent extreme delays
    numOfD = std::min<int>(numOfD,10000);

    for ( int fd=3 ; fd < numOfD ; ++fd )
    {
        int oldFlags = fcntl(fd, F_GETFD, 0);
        fcntl( fd, F_SETFD, oldFlags | FD_CLOEXEC );
    }

#endif
}


void
Process::processesByModule(
    paths_t     const & inModuleFilePaths
,   MultiMap          & outUsedModules
)
{
    outUsedModules.clear();

#if 0
#ifdef _WIN32

    BLOCK
    {
        // convert blacklist file paths to canonical form
        ::std::set<::fs::path>
            blackList;

        for ( int i=0 ; i<inModuleFilePaths.size() ; i++ )
        {
            QString
                fn = QDir::toNativeSeparators(QFileInfo(inModuleFilePaths[i]).canonicalFilePath().toLower());

            blackList.insert(fn);
        }


        // foreach process
        List
            procs;

        retVal << processes(procs);
        BreakOnFail;

        for (int i=0 ; i<procs.size() ; i++)
        {
            Process &
                p = *procs[i];

            // get all modules
            QStringList
                mods;
            p.modules(mods);

            // report the process if the module is blacklisted
            for (int j=0 ; j<mods.size() ; j++)
            {
                QString
                    fn = QDir::toNativeSeparators(QFileInfo(mods[j]).canonicalFilePath().toLower());
                if ( blackList.contains(fn) )
                    outUsedModules.insert(fn,procs[i]);
            }
        }
    }
    FIN
#endif
#endif
}



void
Process::terminate(
    int inExitCode
)
{

#ifdef _WIN32

    HANDLE
        hProcess = INVALID_HANDLE_VALUE;

    BLOCK
    {
        if (DBC_FAIL(processId()!=0))
        {
            Error {u8"2b707fd9-4f56-45cc-bd24-634e0969f34e"_uuid};
            LEAVE;
        }

        hProcess = ::OpenProcess(
                PROCESS_ALL_ACCESS      // __in  DWORD dwDesiredAccess
            ,   false                   // __in  BOOL bInheritHandle
            ,   processId()             // __in  DWORD dwProcessId
            );

        if (!hProcess)
        {
            Error {u8"2e685b5c-0e42-4fcb-9fe2-c62b1add86d6"_uuid};
            LEAVE;
        }

        auto
            ok = ::TerminateProcess(
                    hProcess    // hProcess
                ,   inExitCode  // uExitCode
                );

        if (!ok)
        {
            Error {u8"38b0a047-4eaa-4a24-bac6-1daa3b0cae40"_uuid};
            LEAVE;
        }
    }
    FIN

    CloseHandle(hProcess);

#else
    NYI(u8"fea37ed5-aa8f-4795-893a-a34ef5310358"_uuid);
#endif
}

}
