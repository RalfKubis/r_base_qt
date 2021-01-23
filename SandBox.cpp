// Copyright (C) Ralf Kubis

#include "r_base_qt/SandBox.h"
#include "r_base_qt/file.h"
#include "r_base_qt/filesystem.h"
#include "r_base_qt/string.h"

#include <algorithm>

#ifdef _WIN32
    #include <Windows.h>
#endif

#include <QDir>


namespace nsBase
{

R_DTOR_IMPL(SandBox)
{
    dispose();
}


R_CMOV_IMPL(SandBox)
:   m_id(*src.m_id)
{
    src.id_clear();
}


R_MOVE_IMPL(SandBox)
{
    if (this!=&src)
    {
        dispose();

        ::std::swap(*m_id, *src.m_id);
    }
    return *this;
}


::fs::path
SandBox::base_dir() const
{
    if (base_dir_override_path().empty())
    {
        auto
            path  = Q2P(QDir::tempPath());
            path /= u8"forsa/SandBoxes"_path;

        return path;
    }

    auto
        path  = base_dir_override_path();

    return path;

}


::fs::path
SandBox::path() const
{
    if (!id())
        return {};

    auto
        path  = base_dir();
        path /= S2P(to_string(id()));

    return path;
}


SandBox::ids_t
SandBox::lookup_all(
    ::fs::path base_dir_path
)
{
    ids_t
        ids;

    // collect subdirectories named like a uuid
    foreachSubdirectory(
            base_dir_path
        ,   [&](::fs::path const & dir_path)
                {
                    auto
                        fn = dir_path.filename().u8string();

                    ::uuids::uuid
                        id{fn};

                    if (fn==to_string(id))
                        ids.emplace(id);
                }
        );

    return ids;
}


void
SandBox::generate()
{
    dispose();

    id_assign(::uuids::uuid_system_generator()());

    auto
        p = path();

    ::fs::create_directories(p);

#ifdef _WIN32
    // register the sandbox for removal on system restart
    if (::fs::is_directory(p))
    {
        // calling the unicode version to get rid of the MAX_PATH limit
        MoveFileExW(
                (LPCWSTR)(u"\\\\?\\"_qs + P2Q(p)).utf16() // __in      LPCTSTR lpExistingFileName
            ,   0                           // __in_opt  LPCTSTR lpNewFileName
            ,   MOVEFILE_DELAY_UNTIL_REBOOT // __in      DWORD dwFlags
            );
    }
#endif
}


bool
SandBox::exists() const
{
    if (!id())
        return false;

    return ::fs::is_directory(path());
}


void
SandBox::dispose()
{
    if (!id())
        return;

    auto
        p = path();

    if (::fs::is_directory(p))
        ::fs::remove_all(p);

    release();
}


void
SandBox::release()
{
    id_clear();
}

}
