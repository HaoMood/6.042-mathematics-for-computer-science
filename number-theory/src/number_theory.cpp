/*
 * number_theory.cpp
 * Common algorithms used in number thoery.
 * Hao Zhang
 * 2017.03.11  First release
 */

#include <cmath>
#include <ctime>

#ifndef NDEBUG
#include <iostream>
using std::cout;
using std::endl;
#endif
#include <map>
using std::map;
#include <random>
using std::default_random_engine;
using std::uniform_int_distribution;
#include <stdexcept>
using std::runtime_error;
#include <string>
using std::string;
#include <vector>
using std::vector;

#include "number_theory.h"

long long gcd(const long long k_a, const long long k_b) {
  if (k_a == 0 && k_b == 0) {
    throw runtime_error("gcd(0, 0) is undefined.");
  }
  long long x = (k_a >= 0 ? k_a : -k_a);
  long long y = (k_b >= 0 ? k_b : -k_b);
  if (x < y) {  // Make sure x >= y.
    throw runtime_error("$k_a$ must >= $k_b$");
  }

  while (y != 0) {
    const long long k_r = x % y;
    x = y; 
    y = k_r;
  }
  return x;
}

vector<long long> pulverizer(const long long k_a, const long long k_b) {
  if (k_a == 0 && k_b == 0) {
    throw runtime_error("gcd(0, 0) is undefined.");
  }
  long long x = (k_a >= 0 ? k_a : -k_a);
  long long y = (k_b >= 0 ? k_b : -k_b);
  if (x < y) {  // Make sure x >= y.
    throw runtime_error("$k_a$ must >= $k_b$");
  }

  vector<long long> s(2);
  s[0] = 1;
  s[1] = 0;
  vector<long long> t(2);
  t[0] = 0;
  t[1] = 1;

  while (y != 0) {
    const long long k_r = x % y;
    const long long k_q = (x - k_r) / y;
    x = y; 
    y = k_r;
    const long long k_s0 = s[0];
    const long long k_s1 = s[1];
    s = t;
    t[0] = k_s0 - t[0] * k_q;
    t[1] = k_s1 - t[1] * k_q;
  }
  return s;
}

long long power_modular(const long long k_base, 
                        const long long k_power, 
                        const long long k_mod) {
  const long long k_base_rem = k_base % k_mod;
  long long result = 1;
  for (long long i = 1; i <= k_power; ++i) {
    result = (result * k_base_rem) % k_mod;
  }
  return result;
}

bool isPrimeNaive(const long long k_n) {
  if (k_n <= 1) {
    throw runtime_error("Input must > 1.");
  }
  for (long long i = 2; i <= static_cast<long long>(sqrt(k_n)); ++i) {
    if (k_n % i == 0) {
      return false;
    }
  }
  return true;
}

bool isPrimeProbabilistic(const long long k_n, const long long k_times) {
  default_random_engine engine(time(0));
  uniform_int_distribution<long long> distribution(1, k_n - 1);
  for (long long t = 0; t < k_times; ++t) {
    const long long k_k = distribution(engine);
    if (power_modular(k_k, k_n - 1, k_n) != 1) {
      return false;
    }
  }
  return true;
}

long long generatePrime(const long long k_lower_range, 
                        const long long k_upper_range) {
  default_random_engine engine(time(0));
  uniform_int_distribution<long long> distribution(k_lower_range, 
                                                   k_upper_range);
  while (true) {
    long long random_number = distribution(engine);
    if (isPrimeNaive(random_number)) {
      return random_number;
    }
  }
}

long long inverse(const long long k_k, const long long k_n) {
  if (gcd(k_n, k_k) != 1) {
    throw runtime_error("k and n should be relative prime.");
  }
  vector<long long> s = pulverizer(k_n, k_k);
  long long t = 0;
  for (t = 0; s[1] + t * k_n < 0; ++t) {
    /*empty*/
  }
  return (s[1] + t * k_n) % k_n;
}

long long prepareTuringV1() { 
  return generatePrime(); 
}

long long encryptionTuringV1(const long long k_clean_message,
                             const long long k_key) {
  if (!isPrimeNaive(k_clean_message) || !isPrimeNaive(k_key)) {
    throw runtime_error("Both clean message and key should be prime.");
  }
  long long encrypted_message = k_clean_message * k_key;
  return encrypted_message;
}

long long decryptionTuringV1(const long long k_encrypted_message,
                             const long long k_key) {
  long long clean_message = k_encrypted_message / k_key;
  return clean_message;
}

map<string, long long> prepareTuringV2(const long long k_clean_message) {
  map<string, long long> keys;
  keys["public_key"] = generatePrime(k_clean_message + 1);
  keys["private_key"] = generatePrime(1, keys["public_key"] - 1);
  return keys;
}

long long encryptionTuringV2(const long long k_clean_message,
                             const long long k_p,
                             const long long k_key) {
  if (k_key >= k_p || k_clean_message >= k_p) {
    throw runtime_error(
        "$$k_p$ must < $k_key$ and $k_clean_message$ must < $k_key$");
  }
  if (!isPrimeNaive(k_clean_message) || !isPrimeNaive(k_p) || 
      !isPrimeNaive(k_key)) {
    throw runtime_error(
        "$k_clean_message$, $k_p$, $k_key$ should be prime.");
  }
  long long encrypted_message = (k_clean_message * k_key) % k_p;
  return encrypted_message;
}

long long decryptionTuringV2(const long long k_encrypted_message,
                             const long long k_p,
                             const long long k_key) {
  const long long k_k_inverse = inverse(k_key, k_p);
  long long clean_message = (k_encrypted_message * k_k_inverse) % k_p;
  return clean_message;
}

map<string, map<char, long long>> prepareRsa(
    const long long k_clean_message) {
  long long p = 0;
  long long q = 0;
  long long n = 0;
  long long phi_n = 0;
  do {
    p = generatePrime(k_clean_message + 1);
    q = generatePrime(p + 1);
    n = p * q;
    phi_n = (p - 1) * (q - 1);
  } while(gcd(n, k_clean_message) != 1);
  long long e = 0;  
  do {
    e = generatePrime(1, phi_n - 1);
  } while (gcd(phi_n, e) != 1);
  map<char, long long> public_key;
  public_key['e'] = e;
  public_key['n'] = n;

  long long d = inverse(e, phi_n);
  map<char, long long> private_key;
  private_key['d'] = d;

  map<string, map<char, long long>> keys;
  keys["public_key"] = public_key;
  keys["private_key"] = private_key;
  return keys;
}

long long encryptionRsa(const long long k_clean_message, 
                        const map<char, long long> k_public_key) {
  const long long k_e = k_public_key.at('e');
  const long long k_n = k_public_key.at('n');
  long long encrypted_message = power_modular(k_clean_message, k_e, k_n);
  return encrypted_message;
} 

long long decryptionRsa(const long long k_encrypted_message, 
                        const map<char, long long> k_public_key,
                        const map<char, long long> k_private_key) {
  const long long k_d = k_private_key.at('d');
  const long long k_n = k_public_key.at('n');
  long long clean_message = power_modular(k_encrypted_message, k_d, k_n);
  return clean_message;
}
