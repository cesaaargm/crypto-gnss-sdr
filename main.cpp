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

std::string calculateSHA256();

std::string calculateSHA256_openSSL(const char*);

std::string calculateSHA256_cryptopp(const char*);

bool calculate_ECDSA_openSSL(const char* message);

int main() {

    const char* input = "Hello, World!";
    auto input_unsigned = (const unsigned char*)input;
    for (int i=0 ; i <  strlen(input) - 1 ;i++)
    {
        std::cout << input[i];
        std::cout << input_unsigned[i];
    }
    std::string Sha256_openSSL = calculateSHA256_openSSL(input);

    std::string Sha256_cryptopp = calculateSHA256_cryptopp(input);


    unsigned char array1[] = {1, 2, 3};
    std::cout << sizeof(array1) << std::endl;


    return 0;
}

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

    std::cout << "SHA-256: " << ss.str() << std::endl;
    return ss.str();
}



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
    else
    {
        return false;
    }


    err:
    if(ret != 1)
    {
        /* Do some error handling */
    }

}