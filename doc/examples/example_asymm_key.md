# Asymmetric Key Example

# Asymmetric Key Generation

## Key Generation with default values

The following code is going to generate an RSA key.
A default-spec is an RSASpec with 2048 bit modulus.
In this case, the variable to receive the key is rsaKeyPair.
```cpp
mococrw::AsymmetricKeypair rsaKeyPair = mococrw::AsymmetricKeypair::generateRSA();
```

The following code is going to generate an ECC key.
A default-spec is an ECCspec with a PRIME_256v1 curve (aka NIST P-256 or secp256r1).
In this case, the variable to receive the key is eccKeyPair.
```cpp
mococrw::AsymmetricKeypair eccKeyPair = mococrw::AsymmetricKeypair::generateECC();
```

## Custom Key Generation

It's possible to generate custom keys by providing the generate method with an RSASpec or ECCSpec.

## Custom RSA Key

A default RSA key size is set up in case none is specified by the user.
In this example, the function receives an RSASpec parameter with a size of 1024.
The variable _rsaKeyPair1024 will hold the RSA key generated.
```cpp
mococrw::AsymmetricKeypair rsaKeyPair1024 = mococrw::AsymmetricKeypair::generate(mococrw::RSASpec{1024});
```

## Custom ECC Key

ECCSpec can be created by setting a custom curve type.
List of all supported keys:
```cpp
PRIME_192v1 = NID_X9_62_prime192v1,
PRIME_256v1 = NID_X9_62_prime256v1,
SECP_224r1 = NID_secp224r1,
SECP_384r1 = NID_secp384r1,
SECP_521r1 = NID_secp521r1,
SECT_283k1 = NID_sect283k1,
SECT_283r1 = NID_sect283r1,
SECT_409k1 = NID_sect409k1,
SECT_409r1 = NID_sect409r1,
SECT_571k1 = NID_sect571k1,
SECT_571r1 = NID_sect571r1,
```

```cpp
mococrw::AsymmetricKeypair eccKeyPairSect571r1 = mococrw::AsymmetricKeypair::generate(mococrw::ECCSpec{openssl::ellipticCurveNid::SECT_571r1});
```

# Saving Asymmetric Keys in PEM format

## Writing Public key to Pem

Another functionality of the library is writing the key to a Pem string.
A default RSA key pair is being written to Pem. The process is the same
regardless the key type.

```cpp
const std::string pemOfKey = rsaKeyPair.publicKeyToPem();
```

## Writing Private key to Pem

When writing a private key to a Pem we must give it a password.

```cpp
const std::string pemOfPrivateKey = eccPrivKey.privateKeyToPem("password");
```

# Key Reading from PEM

## Reading a Public Key from a PEM string

The following variables pemEccPrivKeySect409k1 and pemEccPubKeySect409k1 hold a PEM representation of the public and private key, respectively.

Public Key:
```cpp
std::string pemEccPubKeySect409k1{R"(-----BEGIN PUBLIC KEY-----
MH4wEAYHKoZIzj0CAQYFK4EEACQDagAEAAdjoVwkpy9CPA8RU3sd0aXV/XnHw5nE
7HgINd6ApxCaknRebk4Vgbgz04588YqjqQpQTAA+hxkUt1ZInurAHTt/ECQpvt1Y
OTBgNigakbLzq1LsbbyLWJsH5diall6Is+lgy2Mu1EA=
-----END PUBLIC KEY-----)"};
```

```cpp
mococrw::AsymmetricPublicKey eccPubKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(KeyHandlingTests::_pemEccPubKeySect409k1);
```

## Reading a Private Key from PEM

The correct password must be provided to get the private key.
Private Key:
```cpp
std::string pemEccPrivKeySect409k1{R"(-----BEGIN PRIVATE KEY-----
MIHCAgEAMBAGByqGSM49AgEGBSuBBAAkBIGqMIGnAgEBBDQAF2zFhKyxJiI7bGvG
Mw9rq7DUvrqTDJMHeRttpsZc0i9tFbvmaT2J5U39/RkseDha2b87oWwDagAEAAdj
oVwkpy9CPA8RU3sd0aXV/XnHw5nE7HgINd6ApxCaknRebk4Vgbgz04588YqjqQpQ
TAA+hxkUt1ZInurAHTt/ECQpvt1YOTBgNigakbLzq1LsbbyLWJsH5diall6Is+lg
y2Mu1EA=
-----END PRIVATE KEY-----)"};
```

```cpp
mococrw::AsymmetricKeypair eccPrivKey = mococrw::AsymmetricKeypair::readPrivateKeyFromPEM(KeyHandlingTests::_pemEccPrivKeySect409k1, "correct_password");
```
