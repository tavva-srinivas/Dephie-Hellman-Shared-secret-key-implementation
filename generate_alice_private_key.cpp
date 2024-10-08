#include <iostream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

void generate_private_key(Integer &private_key, const Integer &q, AutoSeededRandomPool &rng) {
    // Generate a random number in the range [1, q-1]
    while (true) {
        private_key.Randomize(rng, q.BitCount() - 1);
        // Ensure the private key is in the range [1, q-1]
        if (private_key > 0 && private_key < q) {
            break;
        }
    }
}

void generate_alice_private_key() {
    AutoSeededRandomPool rng;
    Integer g, p, q, alpha;

    // Read parameters from params.bin
    std::ifstream params_file("params.bin", std::ios::binary);
    if (!params_file) {
        std::cerr << "Error: Unable to open params.bin file." << std::endl;
        return;
    }
    params_file >> g >> p >> q;
    params_file.close();

    // Generate private key for Alice (α)
    generate_private_key(alpha, q, rng);

    // Debug: Print the generated private key
    std::cout << "Private Key Alpha (Alice): " << alpha << std::endl;

    // Save private key to file
    std::ofstream fileA("privatekeyA.bin", std::ios::binary);
    if (fileA) {
        fileA << alpha;
        fileA.close();
        std::cout << "Private key for Alice saved to privatekeyA.bin" << std::endl;
    } else {
        std::cerr << "Error: Unable to save private key for Alice." << std::endl;
    }
}

int main() {
    generate_alice_private_key();
    return 0;
}

// Compile and run:
// g++ -std=c++17 -I/opt/homebrew/Cellar/cryptopp/8.9.0/include -L/opt/homebrew/Cellar/cryptopp/8.9.0/lib Lab_Codes/Lab_6/generate_alice_private_key.cpp -lcryptopp -o generate_alice_private_key
// ./generate_alice_private_key
