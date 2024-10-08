#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1  // Enable the use of weak algorithms like MD5

#include <iostream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

void generate_session_key(const std::string &private_key_file, const std::string &other_public_key_file, const std::string &session_key_file, const Integer &p) {
    Integer private_key, other_public_key, session_key;

    // Load private key
    std::ifstream priv_file(private_key_file, std::ios::binary);
    if (!priv_file) {
        std::cerr << "Error: Unable to open " << private_key_file << std::endl;
        return;
    }
    priv_file >> private_key;
    priv_file.close();

    // Load the other party's public key
    std::ifstream pub_file(other_public_key_file, std::ios::binary);
    if (!pub_file) {
        std::cerr << "Error: Unable to open " << other_public_key_file << std::endl;
        return;
    }
    pub_file >> other_public_key;
    pub_file.close();

    // Compute the session key: SSNK ≡ (OtherPublicKey)^PrivateKey mod p
    session_key = a_exp_b_mod_c(other_public_key, private_key, p);

    // Save the session key to a binary file
    std::ofstream sess_file(session_key_file, std::ios::binary);
    if (sess_file) {
        sess_file << session_key;
        sess_file.close();
        std::cout << "Session key saved to " << session_key_file << std::endl;
    } else {
        std::cerr << "Error: Unable to save session key to " << session_key_file << std::endl;
    }

    // Convert session key to a byte array for MD5 hashing
    size_t encodedSize = session_key.MinEncodedSize();
    std::vector<byte> session_key_bytes(encodedSize);
    session_key.Encode(session_key_bytes.data(), encodedSize);

    // Compute and print MD5 hash of the session key for verification
    std::string digest;
    Weak1::MD5 md5;
    StringSource(session_key_bytes.data(), session_key_bytes.size(), true, new HashFilter(md5, new HexEncoder(new StringSink(digest))));
    std::cout << "MD5 of session key (" << session_key_file << "): " << digest << std::endl;
}

void generate_alice_session_key() {
    Integer g, p, q;

    // Load the parameters (g, p, q) from params.bin
    std::ifstream params_file("params.bin", std::ios::binary);
    if (!params_file) {
        std::cerr << "Error: Unable to open params.bin file." << std::endl;
        return;
    }
    params_file >> g >> p >> q;
    params_file.close();

    // Generate Alice's session key
    generate_session_key("privatekeyA.bin", "publicKeyB.bin", "SSNKA.bin", p);
}

int main() {
    generate_alice_session_key();
    return 0;
}

// Compile and run:
// g++ -std=c++17 -I/opt/homebrew/Cellar/cryptopp/8.9.0/include -L/opt/homebrew/Cellar/cryptopp/8.9.0/lib Lab_Codes/Lab_6/generate_alice_session_key.cpp -lcryptopp -o generate_alice_session_key
// ./generate_alice_session_key
