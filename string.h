#pragma once
/* Copyright (C) Ralf Kubis */

#include "r_base/string.h"

#include <QCoreApplication>
#include <QByteArray>
#include <QString>
#include <QChar>



namespace nsBase
{


/**
    Conversion between various String types.

    C - char *
    Q - QString
    S - ::std::string
    O - OFString
    B - QByteArray
*/


////////////////////////////////////////////////////////////
//  char* -> QString
//
inline QString const
    C2Q(char const * const inValue)
        {
            return QString::fromUtf8(inValue);
        }

inline auto
    operator "" _qs(
            char16_t    const * c_str
        ,   ::std::size_t       len
        )
        -> QString
        {
            return QString::fromUtf16(c_str);
        }


////////////////////////////////////////////////////////////
//  QString -> *
//

// Note: Q2C needs to be a macro because the converted QByteArray returned by toUtf8()
// is temporary and thus the const char* would be dangling after a function return.
#define Q2C(inValue) \
    (inValue).toUtf8().constData()


/**
    Convert a QString to a QByteArray.
    The returned buffer is encoded in UTF-8.
*/
inline QByteArray const
    Q2B( QString const & inValue )
        {
            return inValue.toUtf8();
        }

/**
    Convert a QString to a ::std::string.
    The returned string is encoded in UTF-8.
*/
inline ::std::string
    Q2S(
            QString const & inValue
        )
        {
            return Q2C(inValue);
        }

inline ::std::string
    to_string(
            QString const & qs
        )
        {
            return Q2S(qs);
        }


////////////////////////////////////////////////////////////
//  QByteArray -> *
//
inline ::std::string
    B2S(
            QByteArray const & ba
        )
        {
            if (ba.isEmpty())
                return {};

            return {ba.constData(), static_cast<::std::string::size_type>(ba.size())};
        }

inline QString
    B2Q(
            QByteArray const & ba
        )
        {
            if (ba.isEmpty())
                return {};

            return QString::fromUtf8(ba.constData());
        }


////////////////////////////////////////////////////////////
//  ::std::string -> *
//

inline QString
    S2Q(::std::string const & inValue)
        {
            return C2Q(inValue.c_str());
        }

inline QByteArray
    S2B(
            ::std::string const & s
        )
        {
            if (s.empty())
                return {};

            return {s.data(), int(s.size())};
        }



template<class T>
QString
QString_number(
    T value
)
{
    return QString::number(value);
}

template<>
inline
QString
QString_number<double>(
    double value
)
{
    return QString::number(value,'g',666);
}

template<>
inline
QString
QString_number<float>(
    float value
)
{
    return QString_number<double>(value);
}



inline QString
    if_not_empty(QString const & s, QString const & separator)
        {
            return s.isEmpty() ? QString{} : separator;
        }


inline QString
    append_with_separator(QString const & pre, QString const & separator, QString const & post)
        {
            return pre + (pre.isEmpty() ? QString{} : separator) + post;
        }


template<
    typename Collection
,   typename ::std::enable_if_t<::std::is_same<typename ::std::remove_cv<typename Collection::value_type>::type,QString>::value, int> = 0
>
auto
joined(
        Collection    const & lines
    ,   QString       const & delimiter
    )
    ->  QString
    {
        QString
            retVal;

        auto
            count = 0;

        for (auto const & line : lines)
        {
            if (count)
                retVal += delimiter;
            count++;

            retVal += line;
        }

        return retVal;
    }


template<
    typename Collection
,   typename ::std::enable_if_t<!::std::is_same<typename ::std::remove_cv<typename Collection::value_type>::type,QString>::value, int> = 0
>
auto
joined(
        Collection    const & lines
    ,   QString       const & delimiter
    )
    ->  QString
    {
        return S2Q(joined(lines, Q2S(delimiter)));
    }
}


namespace std
{
inline ::std::string
    to_string(
            QString const & qs
        )
        {
            return ::nsBase::Q2S(qs);
        }
}
