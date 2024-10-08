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

void generate_bob_private_key() {
    AutoSeededRandomPool rng;
    Integer g, p, q, beta;

    // Read parameters from params.bin
    std::ifstream params_file("params.bin", std::ios::binary);
    if (!params_file) {
        std::cerr << "Error: Unable to open params.bin file." << std::endl;
        return;
    }
    params_file >> g >> p >> q;
    params_file.close();

    // Generate private key for Bob (β)
    generate_private_key(beta, q, rng);

    // Debug: Print the generated private key
    std::cout << "Private Key Beta (Bob): " << beta << std::endl;

    // Save private key to file
    std::ofstream fileB("privatekeyB.bin", std::ios::binary);
    if (fileB) {
        fileB << beta;
        fileB.close();
        std::cout << "Private key for Bob saved to privatekeyB.bin" << std::endl;
    } else {
        std::cerr << "Error: Unable to save private key for Bob." << std::endl;
    }
}

int main() {
    generate_bob_private_key();
    return 0;
}

// Compile and run:
// g++ -std=c++17 -I/opt/homebrew/Cellar/cryptopp/8.9.0/include -L/opt/homebrew/Cellar/cryptopp/8.9.0/lib Lab_Codes/Lab_6/generate_bob_private_key.cpp -lcryptopp -o generate_bob_private_key
// ./generate_bob_private_key
