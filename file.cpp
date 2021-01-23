/* Copyright (C) Ralf Kubis */

#include "r_base_qt/file.h"
#include "r_base/Error.h"

#include <fstream>


namespace nsBase
{

QByteArray
file_read_all_q(
    ::fs::path const & path
)
{
    auto const
        c_file_size_max_accepted = 100000000_sz;

    ::std::ifstream
        stream(path.u8string(), ::std::ios::binary | ::std::ios::ate);

    if (!stream)
    {
        throw Error(Log(u8"b3a53591-3a7a-4e56-989b-6fea0041a600"_uuid)
            .error()
            .message("unable to open '${path}'")
            .path(path)
            );
    }

    ::std::size_t
        size = stream.tellg();

    if (size > c_file_size_max_accepted)
    {
        throw Error(Log(u8"98fc32fd-0ab4-4ee1-a6f3-9d9c2efe7100"_uuid)
            .error()
            .message("file too large; accepting '${count}' bytes or less ")
            .count(c_file_size_max_accepted)
            );
    }

    QByteArray
        buffer(size,'\0');

    stream.seekg(0);

    if (!stream.read(buffer.data(), size))
    {
        throw Error(Log(u8"c00ea126-d26e-493d-8310-9d804c111cb0"_uuid)
            .error()
            .message("unable to read '${path}'")
            .path(path)
            );
    }

    return buffer;
}


void
file_write_all(
    ::fs::path        const & file_path
,   QByteArray        const & content
,   ::std::ios_base::openmode mode
)
{
    ::std::ofstream
        stream(file_path, mode);
        stream.write(content.data(), content.size()); // throws
}

}
