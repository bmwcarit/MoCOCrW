Hash {#example3}
====================
Hash
====

The following example generates a SHA1 type.
To generate a different hash type the procedure is the same, 
we just need to call the specific method (sha256(), sha512()).
\code{.cpp}
  uint8_t messagePointer[5] = {3,4,5,6,9};
  std::string message1 = "Greathash";
  std::vector<uint8_t> message2 {1,2,3,4};

  auto hash1 = sha1(messagePointer, 5);
  auto hash2 = sha1(message1);
  auto hash2 = sha1(message2);  
\endcode