#pragma once

#include <mococrw/ecies.h>
#include <mococrw/key.h>

#include <boost/program_options.hpp>

using namespace mococrw;
namespace po = boost::program_options;

struct EciesData{
    std::shared_ptr<AsymmetricPublicKey> ephKey;
    std::shared_ptr<AsymmetricPrivateKey> privKey;
    std::shared_ptr<AsymmetricPublicKey> pubKey;
    std::shared_ptr<X509Certificate> cert;
    std::shared_ptr<ECCSpec> eccSpec;
    std::vector<uint8_t> macValue;
    openssl::EllipticCurvePointConversionForm ecForm;
    std::shared_ptr<KeyDerivationFunction> kdfFunc = nullptr;
    std::function<std::unique_ptr<MessageAuthenticationCode>(const std::vector<uint8_t>&)> macFunc = nullptr;
    size_t macKeySize;
    std::vector<uint8_t> data;
    std::shared_ptr<po::variables_map> vm;
    bool chaining;
    EciesData() : ephKey(nullptr), privKey(nullptr), pubKey(nullptr), cert(nullptr), eccSpec(nullptr),
        ecForm(openssl::EllipticCurvePointConversionForm::uncompressed), kdfFunc(nullptr), macFunc(nullptr),
        macKeySize(0), vm(nullptr), chaining(false)
    {}
};

extern bool isPubKeyAnEccKey(const AsymmetricPublicKey &pubKey);
extern void encrypt_ecies(const struct EciesData &eciesData);
extern void decrypt_ecies(const struct EciesData &eciesData);
