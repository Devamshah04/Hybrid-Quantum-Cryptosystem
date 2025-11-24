# **Hybrid Quantum-Safe Cryptosystem**

ML-KEM + AES-256

Devam Shah

## **Introduction and Rationale**

The main reason for the choice of this particular cryptographic scheme is due to the fact that quantum computing will imminently threaten the security of current public-key standards, like RSA and Elliptic Curve Cryptography.

According to the Commercial National Security Algorithm Suite 2.0 or CNSA 2.0 of the NSA, all agencies need to begin phasing out old encryption in favor of quantum-resistant algorithms. Similarly, NIST has recently concluded its post-quantum cryptography standardization process.

In this landscape, ML-KEM -also known as Kyber until recently-was picked by NIST as the main standard for general-purpose encryption: FIPS 203.

This system uses a Hybrid Encryption Scheme:

- _ML-KEM (Mechanism)_: Used exclusively for the secure sharing of a secret. Its mathematical foundation is based on lattices which are resilient to Shor's algorithm.
- _AES-256 (Payload)_: The symmetric cipher applied for the actual bulk data encryption. Theoretically, symmetric ciphers are vulnerable to Grover's algorithm; however, merely doubling to 256-bit key sizes is generally accepted as mitigating that threat, making AES-256 quantum-safe in practice.  

This binding provides compatibility with future cryptographic standards, yet allows symmetric encryption of payload data for speed and efficiency.

## **Security Properties**

_A. ML-KEM (The Key Encapsulation Layer):_

- **Hardness Assumption (ML-LWE):** ML-KEM is based on the Module-Lattice Learning With Errors problem. Unlike RSA (based on factoring) or ECC (based on discrete logarithms), finding the secret vector in a high-dimensional lattice with added "noise" is computationally infeasible for both classical and quantum computers.
- **IND-CCA2 Security:** The underlying Kyber algorithm is designed to be Indistinguishability under Chosen Ciphertext Attack (IND-CCA2) secure. This means an attacker cannot learn information about the plaintext even if they have the ability to decrypt chosen ciphertexts (essentially preventing oracle attacks).
- **Forward Secrecy:** If ephemeral keys are used (generating a new ML-KEM keypair for every session), a compromise of the system in the future does not compromise past messages.

_B. AES-256 (The Data Encryption Layer):_

- **Resistance to Grover's Algorithm:** Quantum computers can search an unsorted database of N items in O(sqrt(N)) time. For a block cipher, this effectively halves the bit-security.
  - AES-128 offers approx. 64 bits of quantum security (breakable).
  - AES-256 offers approx. 128 bits of quantum security (considered unbreakable).
- **Confusion and Diffusion:** The implementation utilizes a Substitution-Permutation Network (SPN). The specific code provided implements the standard Rijndael S-box (Substitution) and Shift Rows/ Mix Columns (Permutation) to ensure that a single bit change in the key or plaintext propagates changes across the entire ciphertext (Avalanche Effect).

## **Performance Trade-offs**

- _Key Generation & Encapsulation_:

ML-KEM is significantly faster than traditional RSA and comparable to Elliptic Curve operations. It relies on matrix multiplications over finite rings, which are CPU-efficient.  

- _Encryption Speed_:

Once the key is established, AES-256 is extremely fast. In production environments (unlike the pure Python educational implementation provided), AES utilizes hardware instruction sets (AES-NI), allowing for throughput of gigabits per second.  

- _Python Implementation Note_:

The provided Python code implements AES mathematically (S-box lookups, Galois Field multiplication). In a real-world scenario, this specific implementation would be slow due to Python's interpreter overhead; however, the algorithm itself is highly efficient.  

- _Ciphertext Size_:

ML-KEM produces larger public keys and ciphertexts than Elliptic Curve Cryptography (ECC). For example, a Kyber-768 ciphertext is 1,088 bytes, whereas an ECC ciphertext might be under 100 bytes. However, this is negligible for modern network bandwidth.

- _State Size_:

The 4x4 state matrix used in AES requires minimal memory (RAM), making it suitable for constrained environments.

## **Real-World Use Cases**

- _Secure Web Browsing (TLS 1.3)_

Browsers (Chrome, Firefox) and servers (Cloudflare, AWS) are already integrating this hybrid approach into the Transport Layer Security (TLS) handshake.  

- _Secure Messaging and VPNs_

End-to-end encrypted messaging apps (like Signal, which recently adopted a similar protocol) and Virtual Private Networks. The KEM ensures that the session keys used for the VPN tunnel cannot be derived by a quantum adversary.  

- _Firmware Updates_

Delivering secure updates to IoT devices or vehicles. AES-256 handles the large binary file efficiently, while ML-KEM ensures the decryption key for the update is transmitted securely, preventing injection of malicious firmware.

## **Conclusion**

The system implemented represents the cutting edge of modern cryptography. By moving away from integer factorization (RSA) and embracing lattice-based cryptography (ML-KEM) alongside robust symmetric encryption (AES-256), this architecture adheres to the NSA's CNSA 2.0 guidelines and ensures data confidentiality in the post-quantum era.

## **References**

The design and rationale for this cryptosystem are based on the following standards, mandates, and educational resources:

- **_Primary Educational Source:_**

- Menezes, A. (Cryptography 101). Kyber and Dilithium \[Video Playlist\]. YouTube. Retrieved from <https://youtube.com/playlist?list=PLA1qgQLL41SSUOHlq8ADraKKzv47v2yrF>

Context: This course provides the foundational mathematical theory (Module-Lattices) and algorithmic steps for the ML-KEM implementation used in this project.  

- National Institute of Standards and Technology (NIST). (2024). FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard.

Context: The official standardization of the Kyber algorithm (ML-KEM) used for the asymmetric layer.  

- National Security Agency (NSA). (2022). Commercial National Security Algorithm Suite 2.0 (CNSA 2.0). Cybersecurity Advisory.

Context: The strategic guidance mandating the shift to quantum-resistant algorithms for National Security Systems.

## **Appendix**

<img width="1476" height="994" alt="image" src="https://github.com/user-attachments/assets/9534722c-60dd-45c6-a941-7d3493ff5f23" />

**Fig-1: Output of the ML-KEM + AES-256 implementation**
