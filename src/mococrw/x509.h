/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#pragma once

#include "asn1time.h"
#include "distinguished_name.h"
#include "key.h"
#include "openssl_wrap.h"

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
     * Get the internal openssl x509 instance.
     *
     * This method can be used when interaction with
     * OpenSSL's native methods is necessary for some
     * reason.
     */
    const X509 *internal() const { return _x509.get(); }
    X509 *internal() { return _x509.get(); }

    /**
     * @brief Verify the validity of a certificate
     *
     * Verifies that a certificate is valid (valdity dates) and
     * issued by a CA in a given trust store. The validation can
     * optionally use a set of intermediate certificates that
     * may be used to create trust chain to one of the CA certificates
     * in the trust store.
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
