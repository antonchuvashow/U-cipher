#ifndef UCIPHER_DIFFCRYPTANALYSIS_H_
#define UCIPHER_DIFFCRYPTANALYSIS_H_
#include "UCipher.h"

class DiffCryptAnalysis {
 private:
  UCipher cipher_{};
  uint8_t texts_number_ = 5;
  const std::vector<uint64_t> diffs_ = {0x4000000,
										0x80800000,
										0x8080000080800000};
 public:
  explicit DiffCryptAnalysis(UCipher cipher) : cipher_(std::move(cipher)) {}

  std::pair<std::vector<std::pair<uint64_t, uint64_t>>,
  std::vector<std::pair<uint64_t, uint64_t>>>
  GenerateCiphertexts(uint64_t diff);

  void DecryptLastOperation(std::vector<std::pair<uint64_t, uint64_t>> &ciphertexts) const;

  [[nodiscard]] uint32_t CrackHighestRound(uint32_t differential,
										   std::vector<std::pair<uint64_t, uint64_t>> &ciphertexts) const;

  void DecryptHighestRound(uint32_t crackedKey, std::vector<std::pair<uint64_t, uint64_t>> &ciphertexts) const;

  std::vector<uint32_t> CrackCipher();
};

#endif //UCIPHER_DIFFCRYPTANALYSIS_H_
