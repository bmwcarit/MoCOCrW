# Message Authentication Code (MAC)

# Message Authentication Code Interface

All the MAC classes (currently only one) implement the methods listed below.
Algorithm-specific parameters are specified via the constructor.

```cpp
class MessageAuthenticationCode {
public:
    ...

    virtual void update(const std::vector<uint8_t>& message) = 0;

    virtual std::vector<uint8_t> finish() = 0;

    virtual void verify(const std::vector<uint8_t>& macValue) = 0;
};
```

# HMAC

## HMAC Creation

The following example shows how to create an HMAC.

```cpp
std::vector<uint8_t> key = {'1', '2', '3', '4', '5', '6'};
std::vector<uint8_t> msg = {'m', 'e', 's', 's', 'a', 'g', 'e'};

mococrw::HMAC hmac = mococrw::HMAC(openssl::DigestTypes::SHA256, key);
hmac.update(msg);
std::vector<uint8_t> mac = hmac.finish();
```

## HMAC Verification

The following example shows how an HMAC is verified. Note, `mococrw::HMAC::verify()` performs a constant time
comparison on the given mac. Do NOT re-calculate the mac and compare it to the given mac on your own.

```cpp
std::vector<uint8_t> key = {'1', '2', '3', '4', '5', '6'};
std::vector<uint8_t> msg = {'m', 'e', 's', 's', 'a', 'g', 'e'};
std::vector<uint8_t> mac = {
    0x13, 0x98, 0x4c, 0x07, 0xd3, 0xc0, 0x5c, 0x02, 0x02,
    0xbe, 0xab, 0x67, 0xa2, 0xa6, 0x10, 0x53, 0x96, 0xef,
    0xc0, 0xbf, 0xbb, 0xd0, 0x4a, 0xe6, 0xe0, 0xc0, 0x5d,
    0xc1, 0x06, 0xf7, 0x74, 0x5e
};

mococrw::HMAC hmac = mococrw::HMAC(openssl::DigestTypes::SHA256, key);
hmac.update(msg);

try {
    hmac.verify(mac); // throws if verification fails
}
catch (const MoCOCrWException &e)  {
    std::cerr << "Verification failed" << std:endl;
    ...
}
```

# CMAC

## CMAC Creation

The following example shows how to create a CMAC. The key size needs to match the selected cipher, i.e. you need a key of
128-bits for AES-128.

```cpp
std::vector<uint8_t> key = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
std::vector<uint8_t> msg = {'m', 'e', 's', 's', 'a', 'g', 'e'};

mococrw::CMAC cmac = mococrw::CMAC(openssl::CmacCipherTypes::AES_CBC_128, key);
cmac.update(msg);
std::vector<uint8_t> mac = cmac.finish();
```

## CMAC Verification

The following example shows how a CMAC is verified. Note, `mococrw::CMAC::verify()` performs a constant time
comparison on the given mac. Do NOT re-calculate the mac and compare it to the given mac yourself.

```cpp
std::vector<uint8_t> key = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
std::vector<uint8_t> msg = {'m', 'e', 's', 's', 'a', 'g', 'e'};
std::vector<uint8_t> mac = {
    0x93, 0xff, 0x8a, 0x52, 0x5b, 0xa9, 0xb8, 0x7f,
    0xe4, 0x65, 0xd4, 0x18, 0x08, 0x8f, 0x00, 0x0c
};

mococrw::CMAC cmac = mococrw::CMAC(openssl::CmacCipherTypes::AES_CBC_128, key);
cmac.update(msg);

try {
    cmac.verify(mac); // throws if verification fails
}
catch (const MoCOCrWException &e)  {
    std::cerr << "Verification failed" << std:endl;
    ...
}
```
