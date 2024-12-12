#include "UCipher.h"
#include <iostream>
#include "DiffCryptAnalysis.h"

int main() {
  UCipher cipher(20);
  DiffCryptAnalysis tool(cipher);
  auto keys = tool.CrackCipher();
  UCipher new_c(keys);
  std::cout << new_c.Decrypt(cipher.Encrypt(102030405));
  return 0;
}