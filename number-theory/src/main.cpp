/*
 * main.cpp
 * Test number_theory.hpp
 * Hao Zhang
 * 2017.03.11  First release
 */

#include <cassert>
#include <iostream>
using std::cout;
using std::endl;
#include <map>
using std::map;
#include <string>
using std::string;
#include <vector>
using std::vector;

#include "number_theory.h"

int main() {
  // Test $gcd$.
  assert(gcd(1147, 899) == 31);
  assert(gcd(26, 21) == 1);

  // Test $pulverizer$.
  vector<long long> s = pulverizer(259, 70);
  assert(s[0] == 3);
  assert(s[1] == -11);

  // Test $isPrimeNaive$.
  assert(isPrimeNaive(2));
  assert(isPrimeNaive(3));
  assert(!isPrimeNaive(4));
  assert(!isPrimeNaive(20));
  assert(isPrimeNaive(23));

  // Test $isPrimeProbabilistic$.
  assert(isPrimeProbabilistic(2));
  assert(isPrimeProbabilistic(3));
  assert(!isPrimeProbabilistic(4));
  assert(!isPrimeProbabilistic(20));
  assert(isPrimeProbabilistic(23));

  // Test $inverse$
  assert(inverse(8, 15) == 2);

  // Test Turing's code v1.
  long long clean_message = 113;
  cout << "Orignal message: " << clean_message << endl;
  long long private_key = prepareTuringV1();
  long long encrypted_message = encryptionTuringV1(clean_message, 
                                                   private_key);
  cout << "Encrypted message of Turing's code v1: " << encrypted_message 
       << endl;
  assert(decryptionTuringV1(encrypted_message, private_key) ==
         clean_message);

  // Test Turing's code v2.
  auto keys = prepareTuringV2(clean_message);
  encrypted_message = encryptionTuringV2(clean_message, 
                                         keys.at("public_key"), 
                                         keys.at("private_key"));
  cout << "Encrypted message of Turing's code v2: " << encrypted_message 
       << endl;
  assert(decryptionTuringV2(encrypted_message, 
                            keys.at("public_key"), 
                            keys.at("private_key"))
         == clean_message);

  // Test RSA.
  auto rsa_keys = prepareRsa(clean_message);
  encrypted_message = encryptionRsa(clean_message, 
                                    rsa_keys.at("public_key"));
  cout << "Encrypted message of RSA: " << encrypted_message << endl;
  assert(decryptionRsa(encrypted_message, 
                       rsa_keys.at("public_key"),
                       rsa_keys.at("private_key")) 
         == clean_message);

  // Use.
  cout << "gcd(50, 21) = " << gcd(50, 21) << endl;
  s = pulverizer(50, 21);
  cout << "pulverizer(50, 21) = (" << s[0] << ", " << s[1] << ")" << endl;
  return 0;
}
