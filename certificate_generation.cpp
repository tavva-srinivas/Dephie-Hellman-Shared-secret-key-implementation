#include <cryptopp/dsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/integer.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <ctime>

using namespace CryptoPP;

std::string get_current_date() {
    std::time_t now = std::time(nullptr);
    char buf[80];
    std::strftime(buf, sizeof(buf), "%a, %d %b %Y", std::localtime(&now));
    return std::string(buf);
}

std::string get_expiration_date() {
    std::time_t now = std::time(nullptr);
    std::tm expiration = *std::localtime(&now);
    expiration.tm_year += 2;  // Two years later
    std::mktime(&expiration);
    char buf[80];
    std::strftime(buf, sizeof(buf), "%a, %d %b %Y", &expiration);
    return std::string(buf);
}

std::string encode_public_key(const Integer& publicKey) {
    // Encode the public key as a byte array
    size_t size = publicKey.MinEncodedSize();
    std::vector<byte> encoded(size);
    publicKey.Encode(encoded.data(), encoded.size());

    // Convert the byte array to a base64 string
    std::string encodedStr;
    StringSource ss(encoded.data(), encoded.size(), true, new Base64Encoder(new StringSink(encodedStr), false));
    return encodedStr;
}

void sign_certificate(const std::string &userEmail, const std::string &caPrivKeyFile, const std::string &userPubKeyFile, const std::string &certFile) {
    AutoSeededRandomPool rng;

    // Load the CA's private key
    DSA::PrivateKey caPrivateKey;
    FileSource privFile(caPrivKeyFile.c_str(), true);
    caPrivateKey.Load(privFile);

    // Load the user's public key (DH public key as Integer)
    Integer userPublicKey;
    std::ifstream pubFile(userPubKeyFile, std::ios::binary);
    if (!pubFile) {
        std::cerr << "Error: Unable to open " << userPubKeyFile << std::endl;
        return;
    }
    pubFile >> userPublicKey;
    pubFile.close();

    // Prepare the certificate data
    std::ostringstream certificateData;
    certificateData << "Issuer Name: IIITA\n";
    certificateData << "Subject ID: " << userEmail << "\n";
    certificateData << "Validity:\n";
    certificateData << "    NotBefore: " << get_current_date() << "\n";
    certificateData << "    NotAfter: " << get_expiration_date() << "\n";
    certificateData << "Signature Algorithm: DSA\n";

    // Encode the public key to a base64 string
    std::string userPubKeyStr = encode_public_key(userPublicKey);
    certificateData << "Subject Public Key: (Diffie-Hellman) " << userPubKeyStr << "\n";

    // Hash the certificate data
    std::string certDataStr = certificateData.str();
    SHA256 hash;
    std::string digest;
    StringSource(certDataStr, true, new HashFilter(hash, new StringSink(digest)));

    // Sign the hash with the CA's private key
    DSA::Signer signer(caPrivateKey);
    std::string signature;
    StringSource ss2(digest, true, new SignerFilter(rng, signer, new StringSink(signature)));

    // Encode the signature as base64
    std::string encodedSignature;
    StringSource ss3(signature, true, new Base64Encoder(new StringSink(encodedSignature), false));

    // Complete the certificate with the signature
    certificateData << "Signature: " << encodedSignature << "\n";

    // Save the certificate to a file
    std::ofstream certFileOut(certFile);
    if (certFileOut) {
        certFileOut << certificateData.str();
        certFileOut.close();
        std::cout << "Certificate generated and saved as " << certFile << "." << std::endl;
    } else {
        std::cerr << "Error: Unable to save certificate to " << certFile << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <user_email> <ca_priv_key_file> <user_pub_key_file> <output_cert_file>" << std::endl;
        return 1;
    }

    std::string userEmail = argv[1];
    std::string caPrivKeyFile = argv[2];
    std::string userPubKeyFile = argv[3];
    std::string certFile = argv[4];

    sign_certificate(userEmail, caPrivKeyFile, userPubKeyFile, certFile);

    return 0;
}

// g++ -std=c++17 -I/opt/homebrew/Cellar/cryptopp/8.9.0/include -L/opt/homebrew/Cellar/cryptopp/8.9.0/lib Lab_Codes/Lab_6/certificate_generation.cpp -lcryptopp -o certificate_generation

// ./certificate_generation partyA@example.com CA_Priv.bin publicKeyA.bin CertificateA.bin
// ./certificate_generation partyB@example.com CA_Priv.bin publicKeyB.bin CertificateB.bin




// ./certificate_generation <user_email> <ca_priv_key_file> <user_pub_key_file> <output_cert_file>