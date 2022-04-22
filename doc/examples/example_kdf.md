# Key Derivation Function (KDF)

# KDF Interface

All the KDF classes implement the method `mococrw::KeyDerivationFunction::deriveKey()` to derive a key
of fixed length from a provided password and salt. Algorithm specific parameters are specified via the constructor.

```cpp
class KeyDerivationFunction
{
public:
    ...

    virtual std::vector<uint8_t> deriveKey(const std::vector<uint8_t> &password, const size_t outputLength,
                                           const std::vector<uint8_t> &salt) = 0;
};
```

# PBKDF2

The following code shows how to derive a key using PBKFD2:

```cpp
std::vector<uint8_t> pw = {'1', '2', '3', '4', '5', '6'};
std::vector<uint8_t> salt = {'7', '8', '9', '0', '1', '2'};
size_t derivedKeyLen = 20;

mococrw::PBKDF2 pbkdf2 = mococrw::PBKDF2(openssl::DigestTypes::SHA256, 100);
std::vector<uint8_t> derivedKey = pbkdf2.deriveKey(pw, derivedKeyLen, salt);
```

# X963KDF

The following code shows how to derive a key using X963KDF:

```cpp
std::vector<uint8_t> pw = {'1', '2', '3', '4', '5', '6'};
std::vector<uint8_t> salt = {'7', '8', '9', '0', '1', '2'};
size_t derivedKeyLen = 20;

mococrw::X963KDF x963kdf = mococrw::X963KDF(openssl::DigestTypes::SHA256);
std::vector<uint8_t> derivedKey = x963kdf.deriveKey(pw, derivedKeyLen, salt);
```
