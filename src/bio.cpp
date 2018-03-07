/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#include <boost/format.hpp>

#include "mococrw/bio.h"

namespace mococrw
{
using namespace openssl;

BioObject::BioObject(Types type) : _bio{_BIO_new(_bioMethodFromType(type))} {}

BIO *BioObject::internal() { return _bio.get(); }

const BIO *BioObject::internal() const { return _bio.get(); }

void BioObject::write(const std::string &buf) { _BIO_puts(_bio.get(), buf); }

void BioObject::write(const std::vector<uint8_t> &buf) {
    int written = _BIO_write(_bio.get(), buf);

    if (written < 0 || static_cast<std::size_t>(written) < buf.size()) {
        auto formattedErrorMsg =
                boost::format{
                        "Could not write all data. Reason unknown (OpenSSL reported a count "
                        "of "
                        "%d)"} % written;
        throw std::runtime_error(formattedErrorMsg.str());
    }
}

std::string BioObject::flushToString()
{
    constexpr int buffsize = 2048;
    std::vector<char> buffer(buffsize);
    std::ostringstream ostream{};
    int count = 0;
    do {
        count = _BIO_gets(_bio.get(), buffer);
        if (count < 0) {
            break;
        }
        if (count > buffsize) {
            // _BIO_gets() reads at most buffer.size() bytes out of a bio so if count is bigger
            // than buffsize, it indicates a bug in OpenSSL or some other severe problem.
            throw new std::runtime_error(
                    "OpenSSL corrupted the memory. Your best option now is to terminate.");
        }
        ostream << std::string{buffer.begin(), buffer.begin() + count};
    } while (count > 0);
    if (count < 0) {
        auto formattedErrorMsg =
                boost::format{
                        "Could not read the string. Reason unknown (OpenSSL reported a count "
                        "of "
                        "%d)"} % count;
        throw std::runtime_error(formattedErrorMsg.str());
    }
    return ostream.str();
}

std::vector<uint8_t> BioObject::flushToVector()
{
    constexpr std::size_t buffSize = 2048;
    std::vector<uint8_t> tmpBuffer;
    std::vector<uint8_t> outputBuffer;
    int count = 0;
    do {
        count = _BIO_read(_bio.get(), tmpBuffer, buffSize);
        if (count < 0) {
            break;
        }
        if (static_cast<std::size_t>(count) > buffSize) {
            throw new std::runtime_error(
                    "OpenSSL corrupted the memory. Your best option now is to terminate.");
        }
        outputBuffer.insert(outputBuffer.end(), tmpBuffer.begin(), tmpBuffer.end());
    } while (count > 0);
    // it seems that _BIO_read returns -1 when the buffer is empty. So no special error handling here
    return outputBuffer;

}

FileBio::FileBio(const std::string &filename, FileMode mode, FileType type)
    : BioObject()
{
    std::string modeStr;
    if (mode == FileMode::READ) {
        modeStr = "r";
    } else if (mode == FileMode::WRITE) {
        modeStr = "w";
    }
    if (type == FileType::BINARY) {
        modeStr = modeStr + "b";
    }

    _bio = _BIO_new_file(filename.c_str(), modeStr.c_str());
}

BIO_METHOD *BioObject::_bioMethodFromType(Types type)
{
    switch (type) {
        case Types::MEM:
            return _BIO_s_mem();
        default:
            auto format = boost::format("Unsupported type: %d") % static_cast<int>(type);
            throw std::runtime_error(format.str());
    }
}
}  // ::mococrw
