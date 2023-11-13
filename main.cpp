#include <iostream>
#include <openssl/sha.h> // SHA-256
#include <openssl/ecdsa.h> // ECDSA
#include <openssl/ec.h>
#include <openssl/evp.h> // ECDSA signing and verifying
#include <openssl/decoder.h> // reading the key pair from file
#include <openssl/core.h>
#include <openssl/pem.h>
#include <openssl/err.h> // ERR_get_error()
#include <iomanip>
#include <cstring>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <fstream> // open .pem file

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
int ECDSA_LoadKeys(const char*  path);
bool ECDSA_Verify_OSSL(const char* message,
                       EVP_PKEY *PublicKey,
                       const unsigned char* DigitalSignature, size_t sizeDS);
void ECDSA_Sign_OSSL(const char* message, EVP_PKEY* PublicKey, void** Signature,size_t* SignatureLength);

// Global variables
EVP_PKEY *ECCPrivateKey{NULL};
EVP_PKEY *ECCPublicKey{NULL};

void printError(const char* Caller);
int main() {
    // Secure Hash Algorithm
    //    const char* input = "Hello, World!";
    //    const char* sha256Input = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f";
    //
    //    std::cout << " SHA 256 :: input string :" << input << std::endl;
    //    std::cout << " SHA 256 :: input string hash :" << sha256Input << std::endl;
    //
    //    std::string Sha256_openSSL = calculateSHA256_openSSL(input);
    //    std::string Sha256_cryptopp = calculateSHA256_cryptopp(input);

    // Public Key Verification
    //    publicKeyVerification();

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

// Functions -- Kroot verification
    /*!
     * \brief
     * Method for testing the ECDSA capabilities of openSSL::libcrypto
     */
void KrootVerification(){
    // ✔️ define the TESLA Key Root (message)
    // ✔️ create an ECDSA-P-256 private and public keys
    // ✔️  create a signature (DS) with the private key and message
    // TODO encrypt message with recipient's public key -- this step is done with my public key instead
    // ✔️ define size of digital signature OR change type and apply respective function to compute size.

    // Parameters
    int ret = 0;
    const char* Kroot = "message to encrypt";
    unsigned char* Signature{nullptr}; // store generated signature here.
    size_t SignatureLength{0};
    const char* pathToKeys = "../keys/2023-10-31-PrivateKey-using-X962-192.pem";
    ECDSA_LoadKeys(pathToKeys);
    ECDSA_Sign_OSSL(Kroot, ECCPrivateKey, reinterpret_cast<void**>(&Signature),&SignatureLength); // Sender signs with its Pr_Key
    // assume the Kroot was encrypted and sent out and received and decrypted and is provided to the sig verification.
    bool resultVerificationKroot = ECDSA_Verify_OSSL(Kroot, //
                                                     ECCPublicKey,
                                                     Signature,
                                                     SignatureLength);

    std::cout << "The Kroot(message) and the Signature provided are valid (true/false): " << resultVerificationKroot << std::endl;
    CRYPTO_free(Signature,__FILE__,__LINE__);
}
    /*!
     * \brief Uses the Elliptic Curve Digital Signature Algorithm to verify that the signature of the message is valid
     * and that it belongs to the private key associated with the public key given.
     * \returns bool with the verification result
     */
bool ECDSA_Verify_OSSL(const char* message, EVP_PKEY *PublicKey, const unsigned char* DigitalSignature, size_t sizeDS){

    /* Questions to answer:
     * pctx is null?
     * engine?
     * convert from bytes to evp_pkey_st
     */

    // Verify the signature with the public key.

    EVP_MD_CTX *mdctx = NULL; // verification context; a struct that wraps the message to be verified.
    int ret = 0; // error

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
void ECDSA_Sign_OSSL(const char* message, EVP_PKEY* PrivateKey, void** Signature, size_t* SignatureLength){
    EVP_MD_CTX *mdctx = NULL;
/* Create the Message Digest Context */
    if(!(mdctx = EVP_MD_CTX_new())) goto err; // EVP_MD_CTX_create();?

/* Initialise the DigestSign operation with SHA256 and the private key */
    if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, PrivateKey)) goto err;

    /* Call update with the message */
    if(1 != EVP_DigestSignUpdate(mdctx, message, strlen(message))) goto err;

    /* Finalise the DigestSign operation */

    /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
     * signature. Length is returned in slen */
    // improvement: use only EVP_DigestSign()?
    if(1 != EVP_DigestSignFinal(mdctx, NULL, SignatureLength)) goto err;
    /* Allocate memory for the signature based on size in slen */
    if(!(*Signature = CRYPTO_malloc(sizeof(unsigned char) * (*SignatureLength),__FILE__,__LINE__))) goto err; // OPENSSL_malloc deprecated
    /* Obtain the signature */
    if(1 != EVP_DigestSignFinal(mdctx,
                                reinterpret_cast<unsigned char*>(*Signature),
                                SignatureLength)) goto err;

    /* Success */
    std::cout << "The signature of" << message << "is: " << reinterpret_cast<unsigned char*>(*Signature) << std::endl;
    /* Clean up */
    err:
        {printError("ECDSA_Sign_OSSL");};

    if(mdctx)
        EVP_MD_CTX_free(mdctx);
}
/*! \brief
     * Loads the private and public keys from a .pem file into the format that OSSL uses for further processing.
     * \returns void
     */
int ECDSA_LoadKeys(const char* path) {
    // ✔️ solve SIGSEG error in OSSL_DECODER_CTX_new_for_pkey =>pointer issues.
    // TODO retrieve PrivateKeyBytes from .pem - right now hard-coded
    // HH: std::string mejor luego lo casteas
    // HH: crea function para printear (static_cast seguramente)
    int ret = 1; // 1 success, 0 failure
    OSSL_DECODER_CTX *dctx;
    EVP_PKEY *pkey = NULL;
    const char *format = NULL;   /* NULL for any format, PEM in the future*/
    const char *structure = NULL; /* any structure */
    const char *keytype =  NULL;//NULL;  /* NULL for any key, "EC" ?*/
    const unsigned char *pass = NULL;
    BIO* bio;
    BIO* bio2;

    const char PrivateKeyBytes[]=R"(
-----BEGIN PRIVATE KEY-----
MG8CAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQIEVTBTAgEBBBiFEFnbUTeMpX5h/kxf
w84/sleueQ2Po3GhNAMyAARBRrSXwzm89f60m9wv4QQvierK5IIw0Ul0Jlttfmkz
qItFLQJBgSBUZCR6623nH8Q=
-----END PRIVATE KEY-----
)";
    const char PublicKeyBytes[]=R"(
-----BEGIN PUBLIC KEY-----
MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQIDMgAEQUa0l8M5vPX+tJvcL+EEL4nqyuSC
MNFJdCZbbX5pM6iLRS0CQYEgVGQkeutt5x/E
-----END PUBLIC KEY-----
)";


    if(!(bio = BIO_new_mem_buf(PrivateKeyBytes, -1))) ret = 0; // -1 == length to be computed
    ECCPrivateKey = PEM_read_bio_PrivateKey(bio,NULL,NULL,NULL);
    if(!(bio2 = BIO_new_mem_buf(PublicKeyBytes, -1))) ret = 0;
    ECCPublicKey =  PEM_read_bio_PUBKEY(bio2,NULL,NULL,NULL);
    //EVP_PKEY_print_private(bio, ECCPrivateKey, 1,NULL); // TODO how to access BIO object
    /*// Read file
    FILE *fp = fopen(path, "r"); if (fp == NULL) ret = 0;
    // set up decoder for processing input data into an EVP_PKEY structure.
    if(!(dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, format,
                                         structure, keytype,
                                         OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                                         NULL, NULL))) ret = 0;
    if (( 1 == OSSL_DECODER_from_fp(dctx,fp))) {
        // pkey is created with the decoded data from the bio
        // did not find any function to read the EPV_PKEY from a CTX..x
        std::cout<< "Pkey loaded into CTX successfuly. " << std::endl;
    } else ret = 0;*/



/*    // Free memory
    OSSL_DECODER_CTX_free(dctx);*/
    BIO_free(bio);
    BIO_free(bio2);

    return ret;
}

void printError(const char* Caller){
    char temp[256];
    char* e =ERR_error_string(ERR_get_error(),temp);
    if (e) {
        // error:[error code]:[library name]::[reason string]
        std::cout <<"Error occurred in " << Caller << std::endl << e << std::endl;
    } else {
        std::cerr << "printError::Error converting error code to string." << std::endl;
    }
}