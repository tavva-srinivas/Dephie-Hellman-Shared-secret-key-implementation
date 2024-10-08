#include <cryptopp/dsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <iostream>

using namespace CryptoPP;

int main() {
    AutoSeededRandomPool rng;

    
    DSA::PrivateKey caPrivateKey;
    DSA::PublicKey caPublicKey;
    caPrivateKey.GenerateRandomWithKeySize(rng, 2048);
    caPrivateKey.MakePublicKey(caPublicKey);

    
    {
        FileSink caPubFile("CA_Pub.bin", true);
        caPublicKey.Save(caPubFile);
    }

    
    {
        FileSink caPrivFile("CA_Priv.bin", true);
        caPrivateKey.Save(caPrivFile);
    }

    std::cout << "CA public and private keys generated and saved as CA_Pub.bin and CA_Priv.bin." << std::endl;

    return 0;
}



// Dependency command 
// g++ -std=c++17 -I/opt/homebrew/Cellar/cryptopp/8.9.0/include -L/opt/homebrew/Cellar/cryptopp/8.9.0/lib Lab_Codes/Lab_6/setupCA.cpp -lcryptopp -o setupCA
// ./setupCA