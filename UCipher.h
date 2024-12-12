#ifndef UCIPHER_UCIPHER_H_
#define UCIPHER_UCIPHER_H_
#include "utils.h"
#include <vector>
#include <random>

class UCipher {
 private:
  const std::vector<uint32_t> keys_{};
 public:
  explicit UCipher(std::vector<uint32_t> keys) : keys_(std::move(keys)) {}
  explicit UCipher(uint8_t key_length_bits = 32) : keys_(GenerateKeys(key_length_bits)) {}

  static std::vector<uint32_t> GenerateKeys(const uint8_t &key_length_bits);

  static uint8_t Rotate(uint8_t a, uint8_t b, uint8_t x, uint8_t pos);
  static uint32_t RoundFunction(uint32_t msg, uint32_t key);

  uint64_t Encrypt(uint64_t msg);

  uint64_t Decrypt(uint64_t msg);

};

#endif //UCIPHER_UCIPHER_H_
