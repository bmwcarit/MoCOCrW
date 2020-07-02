# Hash Example

# Hash One-Shot Functions

The following example generates a SHA1 type using the one-shot interface.
To generate a different hash type the procedure is the same,
we just need to call the specific method.

```cpp
uint8_t messagePointer[5] = {3,4,5,6,9};
std::string message1 = "Greathash";
std::vector<uint8_t> message2 {1,2,3,4};

std::vector<uint8_t> hash1 = mococrw::sha1(messagePointer, 5);
std::vector<uint8_t> hash2 = mococrw::sha1(message1);
std::vector<uint8_t> hash2 = mococrw::sha1(message2);
```

The following algorithms are supported:
- `mococrw::sha1()`
- `mococrw::sha256()`
- `mococrw::sha384()`
- `mococrw::sha512()`
- `mococrw::sha3_256()`
- `mococrw::sha3_384()`
- `mococrw::sha3_512()`

# Other Hash interfaces

MoCOCrW also implements a hash interface that allows giving the content to be hashed
in multiple steps. The following example shows how to use this interface:

```cpp
std::string message1 = "Message1";
uint8_t message2[5] = {3,4,5,6,9};
std::vector<uint8_t> message3 {1,2,3,4};

mococrw::Hash h = mococrw::Hash::sha256();
h.update(message1);
h.update(message2);
h.update(message3);

std::vector<uint8_t> hash = h.digest();
```

This interface supports also supports all the algorithms listed above:
- `mococrw::Hash::sha1()`
- `mococrw::Hash::sha256()`
- `mococrw::Hash::sha384()`
- `mococrw::Hash::sha512()`
- `mococrw::Hash::sha3_256()`
- `mococrw::Hash::sha3_384()`
- `mococrw::Hash::sha3_512()`

