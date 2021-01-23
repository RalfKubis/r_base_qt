#pragma once
/* Copyright (C) Ralf Kubis */

#include "r_base/file.h"
#include "r_base_qt/filesystem.h"

#include <QByteArray>


namespace nsBase
{

// throws
QByteArray
    file_read_all_q(
            ::fs::path const & file_path
        );

// throws
void
    file_write_all(
            ::fs::path        const & file_path
        ,   QByteArray        const & content
        ,   ::std::ios_base::openmode mode = ::std::ios::binary | ::std::ios::trunc
        );
}
