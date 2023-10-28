#include <iostream>
#include <openssl/sha.h> // SHA-256
#include <openssl/ecdsa.h> // ECDSA
#include <openssl/ec.h>
#include <openssl/evp.h> // ECDSA signing and verifying
#include <iomanip>
#include <cstring>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

// Forward declarations -- Secure Hash Algorithm
std::string calculateSHA256_openSSL(const char*);
std::string calculateSHA256_cryptopp(const char*);

// Forward declarations -- Public Key Verification
typedef unsigned char* ByteArray;
bool publicKeyVerification();
ByteArray merkle_tree_computation(ByteArray message,
                                  size_t m_length,
                                  ByteArray intermediateNodes,
                                  size_t itn_length,
                                  ByteArray NPT);
ByteArray concatenate(ByteArray input1,
                      size_t size1,
                      ByteArray input2,
                      size_t size2);
ByteArray sha256(const ByteArray message,
                 size_t length,
                 ByteArray digest);

// Forward declarations -- Key root verification
bool calculate_ECDSA_openSSL(const char* message);


int main() {

    // Secure Hash Algorithm
    const char* input = "Hello, World!";
    const char* sha256Input = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f";

    std::cout << " SHA 256 :: input string :" << input << std::endl;
    std::cout << " SHA 256 :: input string hash :" << sha256Input << std::endl;

    std::string Sha256_openSSL = calculateSHA256_openSSL(input);
    std::string Sha256_cryptopp = calculateSHA256_cryptopp(input);

    // Public Key Verification
    publicKeyVerification();

    return 0;
}

// Functions -- Secure Hash Algorithm
std::string calculateSHA256_cryptopp(const char* input) {
    auto inputData = reinterpret_cast<const CryptoPP::byte*>(input);
    size_t dataLength = strlen(input);
    CryptoPP::SHA256 sha256;
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    // conversion?
    sha256.CalculateDigest(digest,inputData,dataLength);

    // Convert the binary hash to a hex string
    CryptoPP::HexEncoder encoder;
    std::string hash;
    encoder.Attach(new CryptoPP::StringSink(hash));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();
    return hash;
}
std::string calculateSHA256_openSSL(const char* input ) {

    unsigned char digest[SHA256_DIGEST_LENGTH];

    SHA256((const unsigned char*)input, strlen(input), digest);

    // Convert the binary digest to a hexadecimal string
    std::stringstream ss;
    for (unsigned char i : digest) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)i;
    }

    std::cout << " SHA 256 ::    computed hash : " << ss.str() << std::endl;
    return ss.str();
}

// Functions -- Public Key Verification
bool publicKeyVerification() {
    unsigned char new_public_key[33] = {0}; // TODO

    uint16_t l_payload; // coming from DSM-PKR
    uint16_t merkle_tree_id; // coming from DSM-PKR
    constexpr size_t size_of_ITN_in_bytes = 256*4/8; // each node has 32 bytes
    ByteArray intermediate_tree_nodes [size_of_ITN_in_bytes]{0}; // Content to be defined.

    // std::vector<unsigned char> aaaa = {};
    ByteArray new_public_key_type{}; // NPKT coming from DSM-PKR
    ByteArray new_public_key_id; // NPKID coming from DSM-PKR
    ByteArray padding; // = l_payload - 1040 - 33;
    ByteArray computed_merkle_tree_root; // final result of PK verification
    ByteArray stored_merkle_tree_root; // source of truth to validate PK

    auto m_0 = concatenate(new_public_key_type,
                           5,
                           new_public_key_id
            ,5);
    m_0 = concatenate(m_0,5,
                      new_public_key,
                      5);

    computed_merkle_tree_root = merkle_tree_computation(m_0,
                                                        33,
                                                        *intermediate_tree_nodes,
                                                        32,
                                                        new_public_key_type);



    if (stored_merkle_tree_root == computed_merkle_tree_root)
        return true;
    else
        return false;

}
ByteArray merkle_tree_computation(ByteArray message, size_t m_length, ByteArray intermediateNodes,size_t itn_length, ByteArray NPT) {

    ByteArray x_0,x_1,x_2,x_3,x_4 {0};

    auto new_public_key_type_int =  std::strlen(reinterpret_cast<const char*>(NPT));
    switch (new_public_key_type_int) {
        case 1: // ECDSA P-256
            // TODO
            // Compute bottom merkle tree
            unsigned char digest[SHA256_DIGEST_LENGTH];
            x_0 = sha256(message,
                         m_length,
                         digest);
            x_1 = sha256(concatenate(x_0,5,&intermediateNodes[0],5),
                         5,
                         digest);
            x_2 = sha256(concatenate(x_1,5,&intermediateNodes[32],5),
                         5,
                         digest);
            x_3 = sha256(concatenate(x_2,5,&intermediateNodes[64],5),
                         5,
                         digest);
            x_4 = sha256(concatenate(x_3,5,&intermediateNodes[96],5),
                         5,
                         digest);
            break;
        case 3: // ECDSA P-521
            // TODO
            break;
        case 4: // OSNMA alert message => report it
            // TODO
            break;
        default: // Error
            // TODO
            break;

    }

    return x_4;
}
ByteArray sha256(const ByteArray message, size_t length, ByteArray digest ) { // unsigned
    SHA256( message, length, digest);
    return digest;
}
ByteArray concatenate(ByteArray input1,size_t size1, ByteArray input2,size_t size2){
    // Allocate memory for the concatenated array
    ByteArray result = new unsigned char[size1 + size2];

    // Copy the elements from the first array
    std::memcpy(result, input1, size1);

    // Copy the elements from the second array
    std::memcpy(result + size1, input2, size2);

    return result;
}

// Functions -- Key root verification
bool calculate_ECDSA_openSSL(const char* message, evp_pkey_st *PublicKey, const unsigned char* DigitalSignature){
    // TODO: debug PK and DS, strlen of unsigned?

    EVP_MD_CTX *mdctx = NULL;
    int ret = 0;

    /* Create the Message Digest Context */
    if(!(mdctx = EVP_MD_CTX_create())) goto err;

    /* Initialize `key` with a public key */
    // hashes cnt bytes of data at d into the verification context ctx
    if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, PublicKey)) goto err;

    /* Initialize `key` with a public key */
    if(1 != EVP_DigestVerifyUpdate(mdctx, message, strlen(message))) goto err;

    if(1 == EVP_DigestVerifyFinal(mdctx, DigitalSignature, -1))
    {
        return true;
    }
    err:
    if(ret != 1)
    {
        /* Do some error handling */
    }
    return false;
}