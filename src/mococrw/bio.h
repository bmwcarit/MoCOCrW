/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#pragma once
#include <sstream>

#include <boost/format.hpp>

#include "openssl_wrap.h"

namespace mococrw
{
/**
 * Wraps the IO functionality of OpenSSL.
 *
 * There are various kinds of 'basic IO' (BIO)
 * in OpenSSL. These can be configured using the
 * 'Type' enum.
 *
 */
class BioObject
{
public:
    enum class Types;

    explicit BioObject(Types type);
    BIO *internal();
    const BIO *internal() const;
    void write(const std::string &buf);
    void write(const std::vector<uint8_t> &data);

    /**
     * Flush the buffer and return a string.
     *
     * Note that this operation will empty the buffer.
     */
    std::string flushToString();
    /**
     * Flush the buffer and return a vector (for binary data)
     *
     * Note that this operation will empty the buffer.
     */
    std::vector<uint8_t> flushToVector();
protected:
    BioObject() = default;

    openssl::SSL_BIO_Ptr _bio;
    static BIO_METHOD *_bioMethodFromType(Types type);
};

enum class BioObject::Types : int {
    MEM,
    FILE,
};


class FileBio : public BioObject
{
public:
    enum class FileMode
    {
        READ,
        WRITE
    };

    enum class FileType
    {
        TEXT,
        BINARY
    };

    explicit FileBio(const std::string &filename, FileMode mode, FileType type);
};

}  // ::mococrw
