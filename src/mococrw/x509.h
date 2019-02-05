/*
 * #%L
 * %%
 * Copyright (C) 2018 BMW Car IT GmbH
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
#pragma once

#include <type_traits>

#include "asn1time.h"
#include "distinguished_name.h"
#include "key.h"
#include "openssl_wrap.h"
#include "crl.h"

namespace mococrw
{

class X509Certificate
{
public:
    static X509Certificate fromPEM(const std::string &pem);
    static X509Certificate fromPEMFile(const std::string &filename);
    static X509Certificate fromDER(const std::vector<uint8_t> &derData);
    static X509Certificate fromDERFile(const std::string &filename);

    /**
     * Return a PEM representation of this certificate.
     */
    std::string toPEM() const;

    /**
     * Get the distinguished name of this certificate.
     *
     * @return the distinguished name of this certifcate.
     */
    DistinguishedName getSubjectDistinguishedName() const;

    /**
     * Get the distinguished name of the issuer of this certificate.
     *
     * @return the issuer distinguished name of this certificate.
     */
    DistinguishedName getIssuerDistinguishedName() const;

    /**
     * Get the start point of the certificate's validity
     *
     * @return A system_clock::time_point of the start point of validity
     */
    std::chrono::system_clock::time_point getNotBefore() const;

    /**
     * Get the end point of the certificate's validity
     *
     * @return A system_clock::time_point of the end point of validity
     */
    std::chrono::system_clock::time_point getNotAfter() const;

    /**
     * Get the start point of the certificate's validity
     *
     * @return An Asn1Time of the starting poing of validity
     */
    Asn1Time getNotBeforeAsn1() const;

    /**
     * Get the end point of the certificate's validity
     *
     * @return An Asn1Time of the end point of validity
     */
    Asn1Time getNotAfterAsn1() const;

    /**
     * @brief Get the serial number of this certificate
     *
     * @return serial number as uint64_t
     */
    uint64_t getSerialNumber() const;

    /**
     * @brief Get the serial number of this certificate in ASCII decimal as a string
     *
     * Return an ASCII represenation of the serial number as decimal numbers with arbitrary
     * precision.
     *
     * @return The serial number as string
     */
    std::string getSerialNumberDecimal() const;

    /**
     * @brief Get the serial number of this certificate as big endian binary representation.
     *
     * Return a big endian binary representation of the serial number with arbitrary precision.
     *
     * @return The serial number as binary
     */
    std::vector<uint8_t> getSerialNumberBinary() const;

    AsymmetricPublicKey getPublicKey() const;

    /**
     * @brief Verify if the certificate is a CA
     *
     * @return Whether the certificate is a CA or not
     */
    bool isCA() const;

    /**
     * Get the internal openssl x509 instance.
     *
     * This method can be used when interaction with
     * OpenSSL's native methods is necessary for some
     * reason.
     */
    const X509 *internal() const { return _x509.get(); }
    X509 *internal() { return _x509.get(); }

    /**
     * This helper class represents a context of an X509 certificate in which it might be valid
     * or not.
     * Such a context typically contains at least one trusted certificate (typically root CAs,
     * but this is not a requirement), a number of intermediate certificates
     * (non self-signed CAs that are (possibly indrectly) signed by a trusted certificate)
     * and optionally a number of CRLs for these certificates.
     */
    class VerificationContext
    {
    public:
        VerificationContext()
            : _trustedCerts{}
            , _intermediateCerts{}
            , _crls{}
            , _enforceSelfSignedRootCertificate{false}
            , _enforceCrlForWholeChain{false}
            , _verificationCheckTime{}
        {}

        /**
         * Adds a number of trusted certificates to this VerificationContext.
         */
        template<typename Container = std::initializer_list<X509Certificate>>
        VerificationContext& addTrustedCertificates(Container&& trustedCerts)
        {
            _addAll(_trustedCerts, std::forward<Container>(trustedCerts));
            return *this;
        }

        /**
         * Adds a single trusted certificate to this context.
         */
        VerificationContext& addTrustedCertificate(X509Certificate trustedCert)
        {
            _trustedCerts.emplace_back(std::move(trustedCert));
            return *this;
        }

        /**
         * Adds a number of intermediate certificates to this VerificationContext.
         */
        template<typename Container = std::initializer_list<X509Certificate>>
        VerificationContext& addIntermediateCertificates(Container&& intermediateCerts)
        {
            _addAll(_intermediateCerts, std::forward<Container>(intermediateCerts));
            return *this;
        }

        /**
         * Adds a single intermediate certificate to this VerificationContext.
         */
        VerificationContext& addIntermediateCertificate(X509Certificate intermediateCert)
        {
            _intermediateCerts.emplace_back(std::move(intermediateCert));
            return *this;
        }

        /**
         * Adds a number of CRLs to this VerificationContext.
         * Unless the given container contains no elements, this activates CRL checking.
         */
        template<typename Container = std::initializer_list<CertificateRevocationList>>
        VerificationContext& addCertificateRevocationLists(Container&& revocationLists)
        {
            _addAll(_crls, std::forward<Container>(revocationLists));
            return *this;
        }

        /**
         * Adds a single CRL to this VerificationContext.
         * This activates CRL checking.
         */
        VerificationContext& addCertificateRevocationList(CertificateRevocationList revocationList)
        {
            _crls.emplace_back(std::move(revocationList));
            return *this;
        }

        /**
         * Sets a flag that the root certificate should be self signed.
         */
        VerificationContext& enforceSelfSignedRootCertificate()
        {
            _enforceSelfSignedRootCertificate = true;
            return *this;
        }

        /**
         * Sets a flag that CRLs must exist for all CAs that are in a verification chain.
         * This also requires setting enforceSelfSignedRootCertificate since OpenSSL doesn't support
         * checking CRLs for all CAs without having a self signed root certificate present.
         */
        VerificationContext& enforceCrlsForAllCAs()
        {
            _enforceCrlForWholeChain = true;
            return *this;
        }

        /**
         * Sets the time for this verification context. All time based validity checks will check
         * with relation to the given time instead of the current time.
         * This only supports times that are within range of std::time_t.
         * @throw MoCOCrWException if a time was passed that is outside of std::time_t range.
         */
        VerificationContext& setVerificationCheckTime(Asn1Time checkTime);

        /**
         * Does a check to see if the current context is in a good state to verify certificates.
         * Invalid states are:
         *  - enforceCrlsForAllCAs is set, but enforceSelfSignedRootCertificate isn't
         *  - enforceCrlsForAllCAs is set, but no CRLs are present
         *
         * @throw MoCOCrWException if the context is in an invalid state.
         */
        void validityCheck() const;

    private:
        friend X509Certificate;
        std::vector<X509Certificate> _trustedCerts;
        std::vector<X509Certificate> _intermediateCerts;
        std::vector<CertificateRevocationList> _crls;
        bool _enforceSelfSignedRootCertificate;
        bool _enforceCrlForWholeChain;
        boost::optional<std::time_t> _verificationCheckTime;

        template<typename Container1, typename Container2>
        void _addAll(Container1& addTo, Container2&& addThese)
        {
            using Iterator = typename std::conditional<std::is_rvalue_reference<Container2&&>::value,
                decltype(std::make_move_iterator(addThese.begin())),
                decltype(addThese.begin())>::type;

             addTo.insert(addTo.end(),
                          Iterator(addThese.begin()),
                          Iterator(addThese.end()));
        }
    };

    /**
     * @brief Verify the validity of a certificate
     *
     * Verifies that a certificate is valid (valdity dates) and
     * issued by a CA in a given trust store. The validation can
     * optionally use a set of intermediate certificates that
     * may be used to create trust chain to one of the CA certificates
     * in the trust store.
     *
     * This is an abbreviation of creating a VerificationContext from the trusted and intermediate
     * certificates and calling verify(VerificationContext).
     *
     * @param trustStore A vector that contains all trusted root CAs The validation will
     *                   require that the certificate is either directly issued
     *                   by a CA in this trust store or that a chain can be created
     *                   to one of the CAs in the trust store.
     * @param intermediateCAs A vector that contains intermediate CAs that should
     *                        be considered when creating a chain. Please note that it is
     *                        not necessary that all certificates in the vector are actually
     *                        used to construct the chain.
     * @throw MoCOCrWException if the validation fails.
     */
    void verify(const std::vector<X509Certificate> &trustStore,
                const std::vector<X509Certificate> &intermediateCAs) const;

    /**
     * @brief Verify the validity of a certificate
     *
     * Verifies that a certificate is considered valid by a given verification context.
     *
     * This is the case if and only if all of the following are true:
     *
     *  - The given context is valid (see VerificationContext::validityCheck)
     *  - There is a certificate chain where each certificate is signed by its predecessor
     *    that extends from a trusted certificate via any number of intermediate certificates
     *    (possibly zero) to the certificate that is verified.
     *  - If enforceSelfSignedRootCertificate is set, the trusted certificate in the chain must
     *    be self signed.
     *  - All certificates in this chain are valid (valid signature, not expired, ...)
     *  - The certificate chain as a whole is valid (requirements set by key usage,
     *    CA path length, ... of the certificates are fulfilled)
     *  - If at least one CRL is part of this context,
     *    a CRL exists for the CA that issued the checked certificate.
     *  - If enforceCrlsForAllCAs was set, a CRL exists for all CAs in the certificate chain.
     *  - All the CRLs that must exist are valid (valid signature, not expired, ...)
     *  - None of the certificates in the chain are part of their predecessor's CRLs.
     *
     * @param ctx A verification context that describes the environment
     *                        (trusted CAs, intermediate CAs, CRLs,...) in which the certificate
     *                        should be verified.
     * @throw MoCOCrWException if the validation fails.
     */
    void verify(const VerificationContext& ctx) const;

    /**
     * Create a new X509 certificate from an existing openssl certificate.
     * @param ptr a unique pointer to the existing openssl certificate.
     */
    explicit X509Certificate(openssl::SSL_X509_Ptr &&ptr) : _x509{std::move(ptr)} {}

private:
    openssl::SSL_X509_SharedPtr _x509;
};

namespace util {
    /**
     * Read a chain of multiple concatinated certificates in PEM format.
     *
     * @param pemChain A string with PEM certificates just concatenated. They may be
     *                 in multiple lines or in just one line.
     * @return A vector with the loaded certificates in the order they occured in the
     *         PEM string
     * @throw MoCOCrWException if the input or one of the included certificates is invalid
     */
    std::vector<X509Certificate> loadPEMChain(const std::string &pemChain);
}

}  // ::mococrw
