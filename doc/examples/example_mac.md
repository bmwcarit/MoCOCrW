# Message Authentication Code (MAC)

# Message Authentication Code Interface

All the MAC classes (currently only one) implement the methods listed below.
Algorithm specific parameters are specified via the constructor.

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

The following example shows how an HMAC can be verified. Please note that `mococrw::HMAC::verify()` performs a constant time
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
