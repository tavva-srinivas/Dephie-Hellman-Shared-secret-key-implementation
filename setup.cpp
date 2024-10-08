#include <iostream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

bool is_prime(const Integer &n, int iterations = 10) {
    AutoSeededRandomPool rng;
    if (n <= 1)
        return false;
    if (n <= 3)
        return true;
    if (n % 2 == 0 || n % 3 == 0)
        return false;

    Integer d = n - 1;
    int r = 0;
    while (d % 2 == 0) {
        d /= 2;
        r++;
    }

    for (int i = 0; i < iterations; i++) {
        // Generate a random Integer 'a' in the range [2, n-2]
        Integer a = 2 + Integer(rng, n.BitCount() - 1) % (n - 3);
        Integer x = a_exp_b_mod_c(a, d, n);

        if (x == 1 || x == n - 1)
            continue;

        bool continue_outer_loop = false;
        for (int j = 0; j < r - 1; j++) {
            x = a_exp_b_mod_c(x, 2, n);
            if (x == n - 1) {
                continue_outer_loop = true;
                break;
            }
        }

        if (!continue_outer_loop)
            return false;
    }

    return true;
}

void generate_large_prime(Integer &prime, int bit_size, AutoSeededRandomPool &rng) {
    while (true) {
        prime.Randomize(rng, bit_size);
        // Ensure the number is odd
        if (prime % 2 == 0) {
            prime += 1;
        }
        if (is_prime(prime)) {
            break;
        }
    }
}

void setup(int p_size, int q_size) {
    AutoSeededRandomPool rng;
    Integer p, q, g;

    // Generate large primes p and q
    generate_large_prime(p, p_size, rng);
    generate_large_prime(q, q_size, rng);

    // Find a generator g of a subgroup of Zp* of order q
    Integer h;
    do {
        h.Randomize(rng, 2, p - 2);  // Randomize h in range [2, p-2]
        g = a_exp_b_mod_c(h, (p - 1) / q, p);  // g = h^((p-1)/q) mod p
    } while (g == 1);

    // Print the generated values
    std::cout << "Prime p: " << p << "\nPrime q: " << q << "\nGenerator g: " << g << std::endl;

    // Save g, p, q to params.bin
    std::ofstream file("params.bin", std::ios::binary);
    file << g << "\n" << p << "\n" << q << "\n";
    file.close();

    std::cout << "Setup phase complete: params.bin generated.\n";
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <p_size> <q_size>\n";
        return 1;
    }

    int p_size = std::atoi(argv[1]);
    int q_size = std::atoi(argv[2]);

    setup(p_size, q_size);

    return 0;
}

// g++ -std=c++17 -I/opt/homebrew/Cellar/cryptopp/8.9.0/include -L/opt/homebrew/Cellar/cryptopp/8.9.0/lib Lab_Codes/Lab_6/setup.cpp -lcryptopp -o setup
// ./setup 1024 160
