#include <iostream>
#include <openssl/sha.h> // SHA-256
#include <openssl/ecdsa.h> // ECDSA
#include <openssl/ec.h>
#include <openssl/evp.h> // ECDSA signing and verifying
//#include "openssl/crypto.h" //OPENSSL_malloc
#include <openssl/decoder.h> // reading the key pair from file
#include <openssl/pem.h>
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
void KrootVerification();
void ECDSA_LoadKeys(std::string path);
bool ECDSA_Verify_OSSL(const char* message,
                       evp_pkey_st *PublicKey,
                       const unsigned char* DigitalSignature, size_t sizeDS);
void ECDSA_Sign_OSSL(const char* message, EVP_PKEY* PublicKey, void* Signature);


int main() {

    // Secure Hash Algorithm
    const char* input = "Hello, World!";
    const char* sha256Input = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f";

    std::cout << " SHA 256 :: input string :" << input << std::endl;
    std::cout << " SHA 256 :: input string hash :" << sha256Input << std::endl;

    std::string Sha256_openSSL = calculateSHA256_openSSL(input);
    std::string Sha256_cryptopp = calculateSHA256_cryptopp(input);

    // Public Key Verification
    //publicKeyVerification();

    // TESLA Kroot Verification
    KrootVerification();

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

/*!
     * \brief
     * Method for testing the ECDSA capabilities of openSSL::libcrypto
     */
void KrootVerification(){
    // TODO define the TESLA Key Root (message)
    // TODO create an ECDSA-P-256 private and public keys
    // TODO  create a signature (DS) with the private key and message
    // TODO encrypt signature and message with recipient's public key -- this step is omitted
    // TODO debug the
    // TODO define size of digital signature OR change type and apply respective function to comput size.

    // Parameters
    int ret = 0;
    const char* Kroot;
    evp_pkey_st* PublicKey;
    evp_pkey_st* PrivateKey; // structure? create private key with ECC?
    const unsigned char* DS;
    void* Signature = NULL;
    std::string pathToKeys = "";
    ECDSA_LoadKeys(pathToKeys);
    ECDSA_Sign_OSSL(Kroot, PublicKey, Signature);
    bool resultVerificationKroot = ECDSA_Verify_OSSL(Kroot,
                                                     PublicKey,
                                                     DS,
                                                     -1);

    std::cout << "The Kroot and the digital signature provided are: " << resultVerificationKroot << std::endl;
}
    /*!
     * \brief Uses the Elliptic Curve Digital Signature Algorithm to verify that the signature (and key root, part of
     * the signature) belong to the private key associated with the public key given.
     * \returns bool with the verification result
     */
bool ECDSA_Verify_OSSL(const char* message, evp_pkey_st *PublicKey, const unsigned char* DigitalSignature, size_t sizeDS){
    /* Questions to answer:
     * pctx is null?
     * engine?
     * convert from bytes to evp_pkey_st
     */

    // Verify the signature with the public key.

    EVP_MD_CTX *mdctx = NULL; // verification context; a struct that wraps the message to be verified.
    int ret = 0;

    /* Create the Message Digest Context */
    if(!(mdctx = EVP_MD_CTX_new())) goto err; // Allocates and returns a digest context.

    /* Initialize `key` with a public key */
    // hashes cnt bytes of data at d into the verification context ctx
    if(1 != EVP_DigestVerifyInit(mdctx, NULL /*TODO null?*/, EVP_sha256(), NULL, PublicKey)) goto err;

    /* Initialize `key` with a public key */
    if(1 != EVP_DigestVerifyUpdate(mdctx, message, strlen(message))) goto err;

    if(1 == EVP_DigestVerifyFinal(mdctx, DigitalSignature, sizeDS))
    {
        return true;
    }
    err:
    if(ret != 1)
    {
        /* Do some error handling */
        // notify other blocks
        std::cout << "ECDSA_Verify_OSSL()::error " << ret  << std::endl;

    }
    return false;
}

    /*! \brief
     * Uses the Elliptic Curve Digital Signature Algorithm to sign a message with a private key
     * \returns bool with the process result
     */
void ECDSA_Sign_OSSL(const char* message, EVP_PKEY* PublicKey, void* Signature){
    EVP_MD_CTX *mdctx = NULL;
    int ret = 0;
    size_t* SignatureLength {nullptr};
/* Create the Message Digest Context */
    if(!(mdctx = EVP_MD_CTX_new())) goto err;

/* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
    if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, PublicKey)) goto err;

    /* Call update with the message */
    if(1 != EVP_DigestSignUpdate(mdctx, message, strlen(message))) goto err;

    /* Finalise the DigestSign operation */
    /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
     * signature. Length is returned in slen */

    if(1 != EVP_DigestSignFinal(mdctx, NULL,SignatureLength )) goto err;
    /* Allocate memory for the signature based on size in slen */
    if(!(Signature = CRYPTO_malloc(sizeof(unsigned char) * (*SignatureLength),
                                   "",
                                   -1))) goto err; // TODO define
    /* Obtain the signature */
    if(1 != EVP_DigestSignFinal(mdctx,
                                reinterpret_cast<unsigned char*>(Signature)/*totally unsure*/,
                                SignatureLength)) goto err;

    /* Success */
    ret = 1;
        std::cout << "The signature of" << message << "is: " << Signature << std::endl;
    err:
    if(ret != 1)
    {
        /* Do some error handling */
    }

    /* Clean up */
    if(Signature && !ret) CRYPTO_free(Signature,"",-1); // TODO Define
    if(mdctx) EVP_MD_CTX_free(mdctx);
}

void ECDSA_LoadKeys(std::string path) {
    // TODO retrieve PrivateKeyBytes from .pem
    int ret = 0;
    OSSL_DECODER_CTX *dctx;
    EVP_PKEY *pkey = NULL;
    const char *format = "PEM";   /* NULL for any format */
    const char *structure = NULL; /* any structure */
    const char *keytype =  NULL;  /* NULL for any key */
    const unsigned char *pass = NULL;
    const char* PrivateKeyBytes = NULL;
    size_t SizePrivateKey {};
    BIO* bio{nullptr};

    PrivateKeyBytes = "MG8CAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQIEVTBTAgEBBBiFEFnbUTeMpX5h/kxf\n"
                                         "w84/sleueQ2Po3GhNAMyAARBRrSXwzm89f60m9wv4QQvierK5IIw0Ul0Jlttfmkz\n"
                                         "qItFLQJBgSBUZCR6623nH8Q=";
    if(!(bio = BIO_new_mem_buf(PrivateKeyBytes, strlen(PrivateKeyBytes))))goto err;
    // if(!(pkey = PEM_read_bio_PrivateKey(bio,NULL,NULL,NULL))) goto err; segmentation error.

    // set up decoder for processing input data into an EVP_PKEY structure.
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, format,
                                         structure, keytype,
                                         OSSL_KEYMGMT_SELECT_KEYPAIR,
                                         NULL, NULL);

    // or OSSL_DECODER_from_data() ? it is recommended bio, but right now my data is... raw data :D

    if (dctx == NULL) goto err;
    if (OSSL_DECODER_from_bio(dctx, bio)) { //
        /* pkey is created with the decoded data from the bio */
    } else goto err;


    err:
    if(ret != 1)
    {
        /* Do some error handling */
        std::cout<< "Error" << std::endl;
    }
    // Free memory
    OSSL_DECODER_CTX_free(dctx);
    BIO_free(bio);
    // TODO what else?
}
