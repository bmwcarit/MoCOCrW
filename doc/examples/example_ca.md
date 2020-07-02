# Certification Authority Example

# Certification Authority

## Chain of Trust

The example below shows how to create a self-signed root certificate with an RSA key
and use it to sign a new certificate for a CSR.

```cpp
//Generate an RSA key pair
mococrw::AsymmetricKeypair rootRSAKey = mococrw::AsymmetricKeypair::generateRSA();

//Set the desired values on the distinguished name for the self-signed certificate
mococrw::DistinguishedName certDetails = mococrw::DistinguishedName::Builder{}.organizationalUnitName("Car IT")
                                                                              .organizationName("BMW")
                                                                              .countryName("DE")
                                                                              .commonName("BMW internal CA Certificate")
                                                                              .build();

mococrw::DistinguishedName rootCertDetails = mococrw::DistinguishedName::Builder{}.commonName("ImATeapot")
                                                                                  .countryName("DE")
                                                                                  .organizationName("Linux AG")
                                                                                  .organizationalUnitName("Linux Support")
                                                                                  .pkcs9EmailAddress("support@example.com")
                                                                                  .localityName("oben")
                                                                                  .stateOrProvinceName("nebenan")
                                                                                  .serialNumber("08E36DD501941432358AFE8256BC6EFD")
                                                                                  .build();

//Creates a v3 extension to make the certificate a CA with a path length of 1
int pathlength = 1;
mococrw::BasicConstraintsExtension caConstraint{true, pathlength};

//Set the values on the certificate signing parameters
mococrw::CertificateSigningParameters caSignParams = CertificateSigningParameters::Builder{}
            .certificateValidity(Asn1Time::Seconds(60*60*24*365*2 /*~2 years*/))
            .digestType(openssl::DigestTypes::SHA256)
            .addExtension(caConstraint)
            .addExtension(*_exampleUsage)
            .build();

//Create root certificate with serial number 0
uint64_t serialNumber = 0;
mococrw::X509Certificate rootRsaCert = mococrw::CertificateAuthority::createRootCertificate(
            rootRSAKey,
            rootCertDetails,
            serialNumber,
            caSignParams);

//Create CA that starts issuing certificates beginning with serial number 1
uint64_t nextSerialNumber = 1;
mococrw::CertificateAuthority rootRsaCa = mococrw::CertificateAuthority(caSignParams, nextSerialNumber, rootRsaCert, rootRSAKey);

mococrw::AsymmetricKeypair intRSAKey = mococrw::AsymmetricKeypair::generateRSA();

//Create a Certificate signing request with the key for the intermediate certificates and the specific parameters of the new certificate.

mococrw::CertificateSigningRequest csr{certDetails, intRSAKey};

mococrw::X509Certificate intCert = rootRsaCa.signCSR(csr);
```
