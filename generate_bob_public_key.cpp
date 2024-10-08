#include <iostream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

void generate_public_key(const std::string &private_key_file, const std::string &public_key_file, const Integer &g, const Integer &p) {
    Integer private_key, public_key;

    // Read the private key from the file
    std::ifstream priv_file(private_key_file, std::ios::binary);
    if (!priv_file) {
        std::cerr << "Error: Unable to open " << private_key_file << " file." << std::endl;
        return;
    }
    priv_file >> private_key;
    priv_file.close();

    // Calculate the public key: K = g^private_key mod p
    public_key = a_exp_b_mod_c(g, private_key, p);

    // Debug: Print the generated public key
    std::cout << "Public Key (" << public_key_file << "): " << public_key << std::endl;

    // Save the public key to the file
    std::ofstream pub_file(public_key_file, std::ios::binary);
    if (pub_file) {
        pub_file << public_key;
        pub_file.close();
        std::cout << "Public key saved to " << public_key_file << std::endl;
    } else {
        std::cerr << "Error: Unable to save public key to " << public_key_file << std::endl;
    }
}

void generate_bob_public_key() {
    Integer g, p, q;

    // Read parameters from params.bin
    std::ifstream params_file("params.bin", std::ios::binary);
    if (!params_file) {
        std::cerr << "Error: Unable to open params.bin file." << std::endl;
        return;
    }
    params_file >> g >> p >> q;
    params_file.close();

    // Generate public key for Bob
    generate_public_key("privatekeyB.bin", "publicKeyB.bin", g, p);
}

int main() {
    generate_bob_public_key();
    return 0;
}

// Compile and run:
// g++ -std=c++17 -I/opt/homebrew/Cellar/cryptopp/8.9.0/include -L/opt/homebrew/Cellar/cryptopp/8.9.0/lib Lab_Codes/Lab_6/generate_bob_public_key.cpp -lcryptopp -o generate_bob_public_key
// ./generate_bob_public_key
