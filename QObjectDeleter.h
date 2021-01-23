#pragma once

#include <QObject>


namespace nsBase
{

struct QObjectDeleter
{
    void operator()(QObject *o)
    {
        o->deleteLater();
    }
};

}
