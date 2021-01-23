#pragma once

#include <QObject>

#include <vector>


namespace nsBase
{

class QConnectionDisposer
{
    public :
        QConnectionDisposer(QMetaObject::Connection && c)
            :   connection{::std::move(c)}
            {
            }

    public :
        QConnectionDisposer(QConnectionDisposer && dp)
            :   connection{::std::move(dp.connection)}
            {
                dp.connection = {};
            }

    public : QConnectionDisposer &
        operator=(QConnectionDisposer && rhs)
            {
                auto
                    pin {::std::move(rhs)};

                connection = ::std::move(pin.connection);

                return *this;
            }

    public :
        ~QConnectionDisposer()
            {
                QObject::disconnect(connection);
            }

    QMetaObject::Connection
        connection;
};

using qconnection_disposers_t = ::std::vector<QConnectionDisposer>;

}
