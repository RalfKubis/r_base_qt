#pragma once
// Copyright (C) Ralf Kubis

#include "r_base/language_tools.h"
#include "r_base/filesystem.h"
#include "r_base/uuid.h"
#include "r_base/string.h"

#include <set>


namespace nsBase
{

/** A SandBox is a private folder somwhere in the users temporary space.
    The class implements the 'dispose pattern'.
    I.e. The destructor, or a call to dispose() disposes the sandbox folder.
    The SandBox folder name is a uuid.
    The folder is created with a call to generate().
    On cration, the sandbox folder gets registered for removal on system restart.
    This gets handy when the sandbox wasn't deleted due to a release() oder crash.
*/
class SandBox
{
    R_DTOR(SandBox);
    R_CTOR(SandBox) = default;
    R_CCPY(SandBox) = delete;
    R_CMOV(SandBox);
    R_COPY(SandBox) = delete;
    R_MOVE(SandBox);

    public : using
        id_t = ::uuids::uuid;
    public : using
        ids_t = ::std::set<id_t>;

    /// becomes the name of the SandBox folder
    R_PROPERTY_(
            id
        ,   id_t
        )

    /// If empty, the sandbox gets created in the users temporary space
    R_PROPERTY_(
            base_dir_override_path
        ,   ::fs::path
        )

    /**
        Get the folder that contains SandBox folders.
        No folders get created here.
    */
    private : ::fs::path
        base_dir() const;

    /**
        full path a SandBox with the given ID would have.
        No folders get created here.
    */
    public : ::fs::path
        path() const;

    /**
        get the all existing SandBoxes
    */
    public : static ids_t
        lookup_all(
                ::fs::path base_dir_path
            );

    /**
        create a new SandBox
        the SandBox folder gets created
        the current SandBox, if any, gets removed.
        throws in case of error.
    */
    public : void
        generate();

    /**
        Delete the SandBox with all its contents, probably delayed.
    */
    public : void
        dispose();

    /**
        Release the sandbox without deleting any file resources.
        Ite ID gets cleared.
    */
    public : void
        release();

    /**
        test whether the SandBox exists
    */
    public : bool
        exists() const;
};
}
