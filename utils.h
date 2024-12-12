#ifndef UCIPHER_UTILS_H_
#define UCIPHER_UTILS_H_
#include <utility>
#include <map>

class Utils {
 public:
  static std::pair<uint32_t, uint32_t> SplitBlock(uint64_t block);
  static uint64_t MergeBlock(uint32_t left, uint32_t right);

  static std::map<uint8_t, uint32_t> CalculateFrequency(const std::vector<uint8_t> &ciphertext);

  static std::vector<uint64_t> EncodeStringToUint64(const std::string &input);

  static std::vector<uint64_t> ReadFileTo64BitBlocks(const std::string &filename);

  static void WriteBlocksToFile(const std::string &filename, const std::string& blocks);
};

#endif //UCIPHER_UTILS_H_
