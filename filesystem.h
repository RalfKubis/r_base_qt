#pragma once
/* Copyright (C) Ralf Kubis */

#include "r_base_qt/filesystem.h"
#include "r_base_qt/string.h"

#include <QString>
#include <QVariant>



inline QString
    P2Q(
            ::fs::path const & path
        )
        {
            return ::nsBase::S2Q(P2S(path));
        }

inline ::fs::path
    Q2P(
            QString const & qpath
        )
        {
            return S2P(::nsBase::Q2S(qpath));
        }

inline ::std::optional<::fs::path>
    V2P(
            QVariant const & v
        )
        {
            if (v.isNull())
                return {};

            return S2P(::nsBase::Q2S(v.value<QString>()));
        }

//KU: keep nested until we drop Qt 5.4 - moc fails on nested namespace definitions
#ifdef _WIN32
namespace std{ namespace filesystem
#else
namespace std{namespace experimental{ namespace filesystem
#endif
{

inline QString
    S2Q(
            ::fs::path const & path
        )
        {
            return ::nsBase::S2Q(path.u8string());
        }

#ifdef _WIN32
}}
#else
}}}
#endif
