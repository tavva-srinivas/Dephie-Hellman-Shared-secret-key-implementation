#include <cryptopp/dsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <iostream>
#include <string>
#include <sstream>
#include <ctime>
#include <iomanip>

using namespace CryptoPP;

bool IsDateWithinRange(const std::string& notBefore, const std::string& notAfter) {
    std::time_t now = std::time(nullptr);
    
    auto parseDate = [](const std::string& dateStr) -> std::time_t {
        std::tm tm = {};
        std::istringstream ss(dateStr);
        ss >> std::get_time(&tm, "%a, %d %b %Y");
        return std::mktime(&tm);
    };
    
    std::time_t notBeforeTime = parseDate(notBefore);
    std::time_t notAfterTime = parseDate(notAfter);
    
    return (now >= notBeforeTime && now <= notAfterTime);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <certificate_file> <ca_pub_key_file>" << std::endl;
        return 1;
    }

    std::string certFilePath = argv[1];
    std::string caPubKeyFilePath = argv[2];

    // Load the CA's public key from the CA_Pub.bin file (DSA)
    DSA::PublicKey caPublicKey;
    FileSource file(caPubKeyFilePath.c_str(), true);
    caPublicKey.Load(file);

    // Read the certificate file
    std::ifstream certFile(certFilePath);
    std::stringstream buffer;
    buffer << certFile.rdbuf();
    std::string certificate = buffer.str();

    // Extract validity period
    size_t notBeforePos = certificate.find("NotBefore: ");
    size_t notAfterPos = certificate.find("NotAfter: ");
    if (notBeforePos == std::string::npos || notAfterPos == std::string::npos) {
        std::cerr << "Validity period not found in certificate." << std::endl;
        return 1;
    }

    std::string notBefore = certificate.substr(notBeforePos + 11, 16); // 11 to skip "NotBefore: "
    std::string notAfter = certificate.substr(notAfterPos + 10, 16);  // 10 to skip "NotAfter: "

    // Check if the certificate is within its validity period
    if (!IsDateWithinRange(notBefore, notAfter)) {
        std::cerr << "Certificate is not within its validity period." << std::endl;
        return 1;
    }

    // Find the signature position
    size_t signaturePos = certificate.find("Signature: ");
    if (signaturePos == std::string::npos) {
        std::cerr << "Signature not found in certificate." << std::endl;
        return 1;
    }

    std::string certData = certificate.substr(0, signaturePos);
    std::string encodedSignature = certificate.substr(signaturePos + 10); // 10 = length of "Signature: "

    // Decode the Base64-encoded signature
    std::string signature;
    StringSource ss(encodedSignature, true, new Base64Decoder(new StringSink(signature)));

    // Generate a hash of the certificate data using SHA-256
    SHA256 hash;
    std::string digest;
    StringSource(certData, true, new HashFilter(hash, new StringSink(digest)));

    // Verify the signature using DSA
    DSA::Verifier verifier(caPublicKey);
    bool result = verifier.VerifyMessage((const byte*)digest.data(), digest.size(), 
                                         (const byte*)signature.data(), signature.size());

    if (result) {
        std::cout << "Certificate verification succeeded." << std::endl;
    } else {
        std::cerr << "Certificate verification failed." << std::endl;
    }

    return result ? 0 : 1;
}

// g++ -std=c++17 -I/opt/homebrew/Cellar/cryptopp/8.9.0/include -L/opt/homebrew/Cellar/cryptopp/8.9.0/lib Lab_Codes/Lab_6/verify_certificate.cpp -lcryptopp -o verify_certificate

// ./verify_certificate CertificateA.bin CA_Pub.bin
// ./verify_certificate CertificateB.bin CA_Pub.bin