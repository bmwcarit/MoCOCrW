/*
 * #%L
 * %%
 * Copyright (C) 2020 BMW Car IT GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

#include <iostream>

#include "sig_example.h"

std::shared_ptr<MessageSignatureCtx> getRsaSignCtx(const struct SigData &sigData)
{
    std::shared_ptr<MessageSignatureCtx> ctx(nullptr);
    std::shared_ptr<RSASignaturePadding> rsaPadding = sigData.rsaPadding;
    if (!rsaPadding) {
        rsaPadding = std::make_shared<PSSPadding>();
    }

    try {
        ctx = std::make_shared<RSASignaturePrivateKeyCtx>(*sigData.privKey.get(), sigData.digestType,
                                                          rsaPadding);
    }  catch (MoCOCrWException &e) {
        std::cerr << "Please check your RSA key. Failure creating context." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }
    return ctx;
}

std::shared_ptr<MessageSignatureCtx>getEccSignCtx(const struct SigData &sigData)
{

    std::shared_ptr<MessageSignatureCtx> ctx(nullptr);
    try {
        ctx = std::make_shared<ECDSASignaturePrivateKeyCtx>(*sigData.privKey.get(), sigData.digestType,
                                                            sigData.sigFormat);
    }  catch (MoCOCrWException &e) {
        std::cerr << "Please check your ECC key. Failure creating context." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }
    return ctx;
}

std::shared_ptr<MessageSignatureCtx>getEccEdSignCtx(const struct SigData &sigData)
{
    std::shared_ptr<MessageSignatureCtx> ctx(nullptr);
    try {
        ctx = std::make_shared<EdDSASignaturePrivateKeyCtx>(*sigData.privKey.get());
    }  catch (MoCOCrWException &e) {
        std::cerr << "Please check your ECC-Ed key. Failure creating context." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void printChainingData(const struct SigData &sigData)
{
    auto vm = *sigData.vm.get();

    if (vm.count("chaining")) {
        if (vm.count("padding")) {
            std::cout << "--padding " << vm["padding"].as<std::string>() << " ";
            if (vm.count("pss-salt-len")) {
                std::cout << "--pss-salt-len " << vm["pss-salt-len"].as<int>() << " ";
            }
        }

        if (vm.count("hash-algo")) {
            std::cout << "--hash-algo " << vm["hash-algo"].as<std::string>() << " ";
        }

        if (vm.count("signature-format") && sigData.privKey->getType() == AsymmetricKey::KeyTypes::ECC) {
            std::cout << "--signature-format " << vm["signature-format"].as<std::string>() << " ";
        }

        std::cout << "--message " << vm["message"].as<std::string>() << " ";
        std::cout << "--signature ";
    }
}

void sign(const struct SigData &sigData)
{
    std::shared_ptr<MessageSignatureCtx> signCtx;
    switch(sigData.privKey->getType()) {
    case AsymmetricKey::KeyTypes::RSA:
        signCtx = getRsaSignCtx(sigData);
        break;
    case AsymmetricKey::KeyTypes::ECC:
        signCtx = getEccSignCtx(sigData);
        break;
    case AsymmetricKey::KeyTypes::ECC_ED:
        signCtx = getEccEdSignCtx(sigData);
        break;
    default:
        std::cerr << "Unknown key type. Supported are RSA, ECC and ECC_ED";
        exit(EXIT_FAILURE);
    }

    std::vector<uint8_t> signature;
    try {
        signature = signCtx->signMessage(sigData.message);
    }  catch (MoCOCrWException &e) {
        std::cerr << "Failure occurred during signing." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    printChainingData(sigData);
    std::cout << utility::toHex(signature) << std::endl;

}

std::shared_ptr<MessageVerificationCtx> verifyRsa(const struct SigData &sigData)
{
    std::shared_ptr<MessageVerificationCtx> ctx(nullptr);

    std::shared_ptr<RSASignaturePadding> rsaPadding = sigData.rsaPadding;
    if (!rsaPadding) {
        rsaPadding = std::make_shared<PSSPadding>();
    }

    try {
        ctx = std::make_shared<RSASignaturePublicKeyCtx>(*sigData.pubKey.get(), sigData.digestType, rsaPadding);
    }  catch (MoCOCrWException &e) {
        std::cerr << "Please check your RSA key. Failure creating context." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }
    return ctx;
}

std::shared_ptr<MessageVerificationCtx> verifyEcc(const struct SigData &sigData)
{
    std::shared_ptr<MessageVerificationCtx> ctx(nullptr);
    try {
        ctx = std::make_shared<ECDSASignaturePublicKeyCtx>(*sigData.pubKey.get(), sigData.digestType, sigData.sigFormat);
    }  catch (MoCOCrWException &e) {
        std::cerr << "Please check your ECC key. Failure creating context." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }
    return ctx;
}

std::shared_ptr<MessageVerificationCtx> verifyEccEd(const struct SigData &sigData)
{
    std::shared_ptr<MessageVerificationCtx> ctx(nullptr);
    try {
        ctx = std::make_shared<EdDSASignaturePublicKeyCtx>(*sigData.pubKey.get());
    }  catch (MoCOCrWException &e) {
        std::cerr << "Please check your ECC-Ed key. Failure creating context." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void verify(const struct SigData &sigData)
{
    std::shared_ptr<MessageVerificationCtx> verifyCtx;
    switch(sigData.pubKey->getType()) {
    case AsymmetricKey::KeyTypes::RSA:
        verifyCtx = verifyRsa(sigData);
        break;
    case AsymmetricKey::KeyTypes::ECC:
        verifyCtx = verifyEcc(sigData);
        break;
    case AsymmetricKey::KeyTypes::ECC_ED:
        verifyCtx = verifyEccEd(sigData);
        break;
    default:
        std::cerr << "Unknown key type. Supported are RSA, ECC and Edward Curves";
        exit(EXIT_FAILURE);
    }

    try {
        verifyCtx->verifyMessage(sigData.signature, sigData.message);
    } catch (MoCOCrWException &e) {
        std::cerr << "Verification failed!" << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    std::cout << "Verification successful. Signature is valid!" << std::endl;

}


