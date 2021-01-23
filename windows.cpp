#ifdef _WIN32

#define _WIN32_WINNT 0x0501
#define WINVER       0x0501

#include <Winsock2.h> // must be included before windows.h
#include <windows.h>
#include <Wtsapi32.h>
#include <malloc.h>
#include <Winternl.h>
#include <Sddl.h>

#include "r_base_qt/windows.h"

#include <QString>
#include <QByteArray>

#include "r_base/language_tools.h"
#include "r_base/Error.h"
#include "r_base_qt/string.h"

#include <algorithm>


namespace nsBase::windows
{

void
TokenAdjustPrivilege(
    void        * const inTokenHandle
,   char        * const inPrivilegeName
,   bool          const inDoEnable
)
{
    DBC_PRE(inPrivilegeName);

    struct
    {
        DWORD               mCount;
        LUID_AND_ATTRIBUTES mPrivilege[1];
    }
        privs;

    BOOL
        b;

    HANDLE
        tokenHandleIn = (HANDLE)(inTokenHandle);

    //////////////////////////////////////////////////////////////////////
    //  If requested, open the access token of the calling process.
    //
    if (tokenHandleIn==INVALID_HANDLE_VALUE)
    {
        auto b = OpenProcessToken(
                GetCurrentProcess()     // _In_   HANDLE ProcessHandle
            ,   TOKEN_ADJUST_PRIVILEGES // _In_   DWORD DesiredAccess
            ,   &tokenHandleIn          // _Out_  PHANDLE TokenHandle
            );

        throw_on_error_win(b, u8"779f01d9-6a19-4b86-8ff2-4b343fa26619"_uuid);
    }


    throw_on_error_win(tokenHandleIn!=INVALID_HANDLE_VALUE, u8"f61d301a-addc-4d48-9871-764e277c7464"_uuid);

    privs.mCount = 1;
    privs.mPrivilege[0].Attributes
        =   inDoEnable
        ?   (SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_USED_FOR_ACCESS)
        :   SE_PRIVILEGE_REMOVED
        ;

    {
        auto b = LookupPrivilegeValue(
                NULL                            // _In_opt_  LPCTSTR lpSystemName
            ,   inPrivilegeName                 // _In_      LPCTSTR lpName
            ,   &(privs.mPrivilege[0].Luid)     // _Out_     PLUID lpLuid
            );

        throw_on_error_win(b, u8"f12bd836-1eea-4acb-b366-a63d1eb9a8cc"_uuid);
    }

    {
        auto b = AdjustTokenPrivileges(
                tokenHandleIn                   // _In_       HANDLE TokenHandle
            ,   FALSE                           // _In_       BOOL DisableAllPrivileges
            ,   (PTOKEN_PRIVILEGES) &privs      // _In_opt_   PTOKEN_PRIVILEGES NewState
            ,   0                               // _In_       DWORD BufferLength
            ,   NULL                            // _Out_opt_  PTOKEN_PRIVILEGES PreviousState
            ,   NULL                            // _Out_opt_  PDWORD ReturnLength
            );

        throw_on_error_win(b, u8"8a324e2c-2f95-4d61-85cb-7d708b2c0a98"_uuid);
    }
}



#   if (_MSC_VER < 1500)
#       define SE_GROUP_INTEGRITY                 (0x00000020L)
#       define SE_GROUP_INTEGRITY_ENABLED         (0x00000040L)
#   endif


QString const
SidUserAndGroupAttributesToString(
    unsigned long const inValue
)
{
    QString r;

    if (inValue & SE_GROUP_MANDATORY         ) r += u" SE_GROUP_MANDATORY"_qs;
    if (inValue & SE_GROUP_ENABLED_BY_DEFAULT) r += u" SE_GROUP_ENABLED_BY_DEFAULT"_qs;
    if (inValue & SE_GROUP_ENABLED           ) r += u" SE_GROUP_ENABLED"_qs;
    if (inValue & SE_GROUP_OWNER             ) r += u" SE_GROUP_OWNER"_qs;
    if (inValue & SE_GROUP_USE_FOR_DENY_ONLY ) r += u" SE_GROUP_USE_FOR_DENY_ONLY"_qs;
    if (inValue & SE_GROUP_INTEGRITY         ) r += u" SE_GROUP_INTEGRITY"_qs;
    if (inValue & SE_GROUP_INTEGRITY_ENABLED ) r += u" SE_GROUP_INTEGRITY_ENABLED"_qs;
    if (inValue & SE_GROUP_LOGON_ID          ) r += u" SE_GROUP_LOGON_ID"_qs;
    if (inValue & SE_GROUP_RESOURCE          ) r += u" SE_GROUP_RESOURCE"_qs;

    return r;
}



QByteArray
TokenGetInformation(
    HANDLE                    const   inTokenHandle
,   TOKEN_INFORMATION_CLASS   const   inTokenInformationClass
)
{
    DWORD dwSize = 0;

    //  get the buffer size
    auto b = GetTokenInformation(
            inTokenHandle           // _In_       HANDLE TokenHandle
        ,   inTokenInformationClass // _In_       TOKEN_INFORMATION_CLASS TokenInformationClass
        ,   NULL                    // _Out_opt_  LPVOID TokenInformation
        ,   0                       // _In_       DWORD TokenInformationLength
        ,   &dwSize                 // _Out_      PDWORD ReturnLength
        );

    if (!dwSize)
        return {};

    QByteArray
        data;
        data.resize(dwSize);

    //  get the data
    b = GetTokenInformation(
            inTokenHandle           // _In_       HANDLE TokenHandle
        ,   inTokenInformationClass // _In_       TOKEN_INFORMATION_CLASS TokenInformationClass
        ,   data.data()             // _Out_opt_  LPVOID TokenInformation
        ,   dwSize                  // _In_       DWORD TokenInformationLength
        ,   &dwSize                 // _Out_      PDWORD ReturnLength
        );

    throw_on_error_win(b, u8"c224ea94-663b-415e-8549-7cfb1202de47"_uuid);
}


QString
TokenDump_LUID_AND_ATTRIBUTES(
    LUID_AND_ATTRIBUTES & inValue
)
{
    DWORD sz = 256;

    QByteArray
        name;
        name.resize(sz);

    auto b = LookupPrivilegeName(
            NULL            // _In_opt_   LPCTSTR lpSystemName
        ,   &inValue.Luid   // _In_       PLUID lpLuid
        ,   name.data()     // _Out_opt_  LPTSTR lpName
        ,   &sz             // _Inout_    LPDWORD cchName
        );

    if (!b)
        name = "[unknown]";
    else
        name.resize(sz);

    return u"%1  [0x%2]"_qs
        .arg(B2Q(name))
        .arg((ulong)inValue.Attributes, 0, 16, QChar(' '))
        ;
}



QString
TokenDump_SID_AND_ATTRIBUTES(
    SID_AND_ATTRIBUTES const & inValue
)
{
    // lookup the account name
    DWORD    nameLen = 256+1;
    DWORD    domaLen = 256+1;

    ::std::string name;
    ::std::string doma;
    ::std::string sid{"UNKNOWN-SID"};

    name.resize(nameLen);
    doma.resize(domaLen);

    ::std::fill(name.begin(), name.end(), '\0');
    ::std::fill(doma.begin(), doma.end(), '\0');

    SID_NAME_USE
        sidType;

    auto b = LookupAccountSid(
            NULL            // _In_opt_   LPCTSTR lpSystemName
        ,   inValue.Sid     // _In_       PSID lpSid
        ,   name.data()     // _Out_opt_  LPTSTR lpName
        ,   &nameLen        // _Inout_    LPDWORD cchName
        ,   doma.data()     // _Out_opt_  LPTSTR lpReferencedDomainName
        ,   &domaLen        // _Inout_    LPDWORD cchReferencedDomainName
        ,   &sidType        // _Out_      PSID_NAME_USE peUse
        );

    if (!b)
    {
        if (GetLastError()==ERROR_NONE_MAPPED)
            name = "ERROR_NONE_MAPPED";
    }

    LPTSTR sidStr {};

    b = ConvertSidToStringSid(
            inValue.Sid //  _In_   PSID Sid
        ,   &sidStr     //  _Out_  LPTSTR *StringSid
        );

    if (!b)
    {
        DBC_ASSERT(!sidStr);
        sid = sidStr;
        LocalFree(sidStr);
        sidStr = {};
    }

    return u"[%1]  [%2\\\\%3]  [%4]"_qs
        .arg(S2Q(sid))
        .arg(S2Q(doma))
        .arg(S2Q(name))
        .arg(SidUserAndGroupAttributesToString(inValue.Attributes))
        ;
}



Log
TokenLog(
    ::uuids::uuid const & issuer_id
,   QString       const   inMessage
,   void        * const   inTokenHandle
)
{
    Log
        log {issuer_id};

//    theLog.printf("<token> [%s]",Q2C(inMessage));

    HANDLE
        tokenHandleIn = (HANDLE)(inTokenHandle);
    HANDLE
        hTokenSelf = INVALID_HANDLE_VALUE;
    HANDLE
        hToken = tokenHandleIn;

    QByteArray
        tokData;



    BLOCK
    {
        //////////////////////////////////////////////////////////////////////
        //  Open a handle to the access token for the calling process.
        //
        BLOCK
        {
            if (hToken!=INVALID_HANDLE_VALUE)
                LEAVE;

            auto b = OpenProcessToken(
                    GetCurrentProcess() // _In_   HANDLE ProcessHandle
                ,   TOKEN_QUERY         // _In_   DWORD DesiredAccess
                ,   &hTokenSelf         // _Out_  PHANDLE TokenHandle
                );

            if (!b)
                LEAVE;

            hToken = hTokenSelf;
        }
        FIN

        if (hToken==INVALID_HANDLE_VALUE)
            LEAVE;


//  TokenGroups


//        theLog.printf("    <TokenGroups>");

        BLOCK
        {
            auto tokData = TokenGetInformation(
                    hToken      // HANDLE                  const   inTokenHandle
                ,   TokenGroups // TOKEN_INFORMATION_CLASS const   inTokenInformationClass
                );

            TOKEN_GROUPS *
                info = (TOKEN_GROUPS*)tokData.data();

            for (DWORD i=0 ; i<info->GroupCount ; i++)
            {
                //theLog.printf(
                //       "        %s"
                //    ,   Q2C( win32TokenDump_SID_AND_ATTRIBUTES( info->Groups[i] ) )
                //    );
            }
        }
        FIN

//        theLog.printf("    </TokenGroups>");


//  TokenPrivileges


//        theLog.printf("    <TokenPrivileges>");
        BLOCK
        {
            auto tokData = TokenGetInformation(
                    hToken          // HANDLE                  const   inTokenHandle
                ,   TokenPrivileges // TOKEN_INFORMATION_CLASS const   inTokenInformationClass
                );

            TOKEN_PRIVILEGES *
                info = (TOKEN_PRIVILEGES*)tokData.data();

            for (DWORD i=0 ; i<info->PrivilegeCount ; i++)
            {
                //theLog.printf(
                //       "        %s"
                //    ,   Q2C( win32TokenDump_LUID_AND_ATTRIBUTES( info->Privileges[i] ) )
                //    );
            }
        }
        FIN

//        theLog.printf("    </TokenPrivileges>");
    }
    FIN

//    theLog.printf("</token> [%s]",Q2C(inMessage));



//  cleanup
//
    CloseHandle(hTokenSelf);

    return ::std::move(log);

//  TokenUser
//  TokenGroups
//  TokenOwner
//  TokenPrimaryGroup
//  TokenDefaultDacl
//  TokenSource
//  TokenType
//  TokenImpersonationLevel
//  TokenStatistics
//  TokenRestrictedSids
//  TokenSessionId
//  TokenGroupsAndPrivileges
//  TokenSessionReference
//  TokenSandBoxInert
//  TokenAuditPolicy
//  TokenOrigin
//  TokenElevationType
//  TokenLinkedToken
//  TokenElevation
//  TokenHasRestrictions
//  TokenAccessInformation
//  TokenVirtualizationAllowed
//  TokenVirtualizationEnabled
//  TokenIntegrityLevel
//  TokenUIAccess
//  TokenMandatoryPolicy
//  TokenLogonSid
//  TokenIsAppContainer
//  TokenCapabilities
//  TokenAppContainerSid
//  TokenAppContainerNumber
//  TokenUserClaimAttributes
//  TokenDeviceClaimAttributes
//  TokenRestrictedUserClaimAttributes
//  TokenRestrictedDeviceClaimAttributes
//  TokenDeviceGroups
//  TokenRestrictedDeviceGroups
//  TokenSecurityAttributes
//  TokenIsRestricted
}


void *
Login(
    QString const & inUserName
,   QString const & inUserPassword
)
{
    HANDLE
        hToken4Imperso = INVALID_HANDLE_VALUE;

    BLOCK
    {
        ::std::string userName;
        ::std::string domain;

        auto backslash = inUserName.indexOf(QChar('\\'));
        if (backslash >= 0) // User name in down-level format?
        {
            domain   = Q2S(inUserName.mid(0, backslash));
            userName = Q2S(inUserName.mid(backslash + 1));
        }
        else
        {
            userName = Q2S(inUserName);

            // Check if user name is in UPN format (user@domain).
            // If not, assume this is a local account.
            if (!inUserName.contains(QChar('@')))
                domain = ".";
        }

        char const * strUserName = userName.c_str();
        char const * strDomain   = domain.empty() ? 0 : domain.c_str();

        // logon user - create token
        auto b = LogonUser(
                strUserName                      // __in      LPTSTR lpszUsername
            ,   strDomain                        // __in_opt  LPTSTR lpszDomain
            ,   inUserPassword.toLatin1().data() // __in      LPTSTR lpszPassword
            ,   LOGON32_LOGON_INTERACTIVE        // __in      DWORD dwLogonType
            ,   LOGON32_PROVIDER_DEFAULT         // __in      DWORD dwLogonProvider
            ,   &hToken4Imperso                  // __out     PHANDLE phToken
            );

        if (!b)
            LEAVE;
    }
    FIN

    return hToken4Imperso;
}



Impersonation::Impersonation(
    void * inAccessToken
)
{
    mIsImpersonated = impersonate(inAccessToken);
}



Impersonation::~Impersonation()
{
    dispose();
}



bool
Impersonation::impersonate(
    void * inAccessToken
)
{
    HANDLE
        hToken4Imperso = (HANDLE)(inAccessToken);

//    TokenLog( "Pre Impersonation" );
//    TokenLog( "Pre Impersonation - NewToken", inAccessToken );

    return ImpersonateLoggedOnUser(
            hToken4Imperso // _In_  HANDLE hToken
        );

//    TokenLog( "Post Impersonation" );
}


void
Impersonation::dispose()
{
    if (mIsImpersonated)
    {
        if (!RevertToSelf())
            Error{u8"95450b58-895e-42fd-ac98-1d6ddc5473ad"_uuid};

        // TokenLog("Post RevertToSelf()");

        mIsImpersonated = false;
    }
}

}

#endif
