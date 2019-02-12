Certification Authority Example {#example2}
===========================================
Certification Authority
=======================

Chain of Trust 
--------------
The example bellow shows how to create a self-signed root certificate with an RSA key
and use it to sign a new certificate with a CSR

\code{.cpp}
//Generate an RSA key pair
AsymmetricKeypair rootRSAKey = AsymmetricKeypair::generateRSA();

//Set the desired values on the distinguished name for the self-signed certificate
DistinguishedName certDetails = DistinguishedName::Builder{}.organizationalUnitName("Car IT")
                                                               .organizationName("BMW")
                                                               .countryName("DE")
                                                               .commonName("BMW internal CA Certificate").build();

DistinguishedName rootCertDetails = DistinguishedName::Builder{}.commonName("ImATeapot")
                                                               .countryName("DE")
                                                               .organizationName("Linux AG")
                                                               .organizationalUnitName("Linux Support")
                                                               .pkcs9EmailAddress("support@example.com")
                                                               .localityName("oben")
                                                               .stateOrProvinceName("nebenan")
                                                               .serialNumber("08E36DD501941432358AFE8256BC6EFD")
                                                               .build();

//Creates a v3 extension to make the certificate a CA with a path length of 1
BasicConstraintsExtension caConstraint{true, 1};

//Set the values on the certificate signing parameters
CertificateSigningParameters caSignParams = CertificateSigningParameters::Builder{}
            .certificateValidity(Asn1Time::Seconds(120))
            .digestType(openssl::DigestTypes::SHA256)
            .addExtension(caConstraint)
            .addExtension(*_exampleUsage)
            .build();

X509Certificate rootRsaCert = CertificateAuthority::createRootCertificate(
            rootRSAKey,
            rootCertDetails,
            0,
            caSignParams);

CertificateAuthority rootRsaCa = CertificateAuthority(caSignParams, 1, rootRsaCert, rootRSAKey);

AsymmetricKeypair intRSAKey = AsymmetricKeypair::generateRSA();

//Create a Certificate signing request with the key for the intermediate certificates and the specific parameters of the new certificate.

CertificateSigningRequest csr{certDetails, intRSAKey};

X509Certificate intCert = rootRsaCa.signCSR(csr);

//The generation of a client certificate implies setting the CA constraint extension to false. 

BasicConstraintsExtension clientConstraint{false, 1};
\endcode