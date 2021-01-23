#pragma once
/* Copyright (C) Ralf Kubis */

#ifdef _WIN32

#include "r_base/Log.h"

#include <QString>


namespace nsBase::windows
{
/**
    Log the given access Token.

    \param  inMessage       An extra message that is logged too.
    \param  inTokenHandle   Handle to the access token.
*/
Log
    TokenLog(
            ::uuids::uuid const & issuer_id
        ,   QString       const inMessage
        ,   void        * const inTokenHandle = (void*)(-1) // INVALID_HANDLE_VALUE
        );


/**
    Adjust a Privilege of the given target access token. Note that the list
    of privileges stored in the token cannot get modified. This function can
    only enable or disable a Privilege that is already in this list. In case
    the targeted Privilege is not part of the token, the function does
    nothing and reports success.

    \param  inTokenHandle   Handle to the target access token. If set
        to INVALID_HANDLE_VALUE, the current processes access token is
        addressed. The token must have been opened with the
        TOKEN_ADJUST_PRIVILEGES flag.
    \param  inPrivilegeName Name of the Privilege to modify.
    \param  inDoEnable              TRUE to grant the Privilege, FALSE to
        deny.
*/
void
    TokenAdjustPrivilege(
            void        * const inTokenHandle
        ,   char        * const inPrivilegeName
        ,   bool          const inDoEnable
        );


/**
    Close handle with CloseHandle() and set it to INVALID_HANDLE_VALUE
    in case the Handle is not set to INVALID_HANDLE_VALUE already.
*/
template<typename T_handle>
    void
        CloseHandle(
                T_handle & inoutHandle
            )
            {
                if (inoutHandle != INVALID_HANDLE_VALUE)
                {
                    ::CloseHandle(inoutHandle);
                    inoutHandle = INVALID_HANDLE_VALUE;
                }
            }


/**
    Login a user and return the access token.

    \param inUserName     The users name.
    \param inUserPassword The users password.

    \return
    -1 in case of failure, the token handle on success.
*/
void *
    Login(
            QString const & inUserName
        ,   QString const & inUserPassword
        );


/**
    RAII class to keep the current thread impersonated to the given access token
    until object destruction.
*/
class Impersonation
{
    /**
        Constructor.

        \param [in] inAccessToken   The access token to impersonate with.
    */
    public :
        Impersonation(
                void * inAccessToken
            );

    public :
        ~Impersonation();

    /**
        Impersonate with the given access token.

        \param [in] inAccessToken   The access token to impersonate with.

        \return
        The success status.
    */
    public : static bool
        impersonate(
                void * inAccessToken
            );

    public : void
        dispose();

    private : bool
        mIsImpersonated;

    public : bool
        isImpersonated() const
            {
                return mIsImpersonated;
            }
};

}
#endif
