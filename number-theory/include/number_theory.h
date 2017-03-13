/*
 * number_theory.h
 * Common algorithms used in number thoery.
 * Hao Zhang
 * 2017.03.11  First release
 */

#ifndef NUMBER_THEORY_
#define NUMBER_THEORY_

#include <map>
#include <string>
#include <vector>

//@brief Compute the gcd of $k_a$ and $k_b$, assume $k_a >= k_b$.
long long gcd(const long long k_a, const long long k_b);

//@brief Find the linear combination coefficients of $gcd(k_a, k_b)$
//   in terms of $k_a$ and $k_b$, assume $k_a >= k_b$.
std::vector<long long> pulverizer(const long long k_a, const long long k_b);

//@brief Compute $k_base$^$k_power$  (mod $k_mod$).
long long power_modular(const long long k_base, 
                        const long long k_power, 
                        const long long k_mod);

//@brief Test whether $k_n$ is prime.
bool isPrimeNaive(const long long k_n);

//@brief Test whether $k_n$ is prime.
bool isPrimeProbabilistic(const long long k_n, const long long k_times = 50);

//@brief Generate a random number in the range 
//   [$k_lower_range$, $k_upper_range$].
long long generatePrime(const long long k_lower_range = 1, 
                        const long long k_upper_range = 1000);

//@brief Compute multiplicative inverse of $k_n$ in $Z_k_mod$.
long long inverse(const long long k_n, const long long k_mod);

//@brief Generate the key used for Turing's code v1.
long long prepareTuringV1(); 

//@brief Encryption by Turing's code v1.
long long encryptionTuringV1(const long long k_clean_message, 
                             const long long k_key);

//@brief Decryption by Turing's code v1.
long long decryptionTuringV1(const long long k_encrypted_message, 
                             const long long k_key);

//@brief Generate the keys used for Turing's code v2.
std::map<std::string, long long> prepareTuringV2(
    const long long k_clean_message);

//@brief Encryption by Turing's code v2.
long long encryptionTuringV2(const long long k_clean_message, 
                             const long long k_public_key,
                             const long long k_private_key);

//@brief Decryption by Turing's code v2.
long long decryptionTuringV2(const long long k_encrypted_message, 
                             const long long k_public_key,
                             const long long k_private_key);

//@brief Generate the keys used for RSA.
std::map<std::string, std::map<char, long long>> prepareRsa(
    const long long k_clean_message);

//@brief Encryption by RSA.
long long encryptionRsa(const long long k_clean_message, 
                        const std::map<char, long long> k_public_key);

//@brief Decryption by RSA.
long long decryptionRsa(const long long k_encrypted_message, 
                        const std::map<char, long long> k_public_key,
                        const std::map<char, long long> k_private_key);

#endif  // NUMBER_THEORY_
