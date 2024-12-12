#include "utils.h"
#include <iostream>
#include <fstream>

std::pair<uint32_t, uint32_t> Utils::SplitBlock(uint64_t block) {
  return {block >> 32, block & 0xFFFFFFFF};
}

uint64_t Utils::MergeBlock(uint32_t left, uint32_t right) {
  return (static_cast<uint64_t>(left) << 32) | right;
}

std::map<uint8_t, uint32_t> Utils::CalculateFrequency(const std::vector<uint8_t> &ciphertext) {
  std::map<uint8_t, uint32_t> frequency_map;

  // Подсчитываем частоту каждого символа
  for (uint8_t c : ciphertext)
	frequency_map[c]++;

  for (const auto &entry : frequency_map) {
	std::cout << static_cast<int>(entry.first) << " "
			  << entry.second << std::endl;
  }

  return frequency_map;
}

std::vector<uint64_t> Utils::EncodeStringToUint64(const std::string &input) {
  std::vector<uint64_t> output;

  size_t padding = (8 - input.size() % 8) % 8;
  std::string padded_input = input + std::string(padding, '\0');

  for (size_t i = 0; i < padded_input.size(); i += 8) {
	uint64_t block = 0;

	// Преобразуем 8 символов в uint64_t
	for (size_t j = 0; j < 8; ++j) {
	  block |= (static_cast<uint64_t>(padded_input[i + j]) << (8 * (7 - j)));
	}

	output.push_back(block);
  }

  return output;
}

std::vector<uint64_t> Utils::ReadFileTo64BitBlocks(const std::string &filename) {
  std::vector<uint64_t> blocks;
  std::ifstream file(filename, std::ios::binary);

  if (!file) {
	std::cerr << "Error: Could not open file " << filename << std::endl;
	return blocks;
  }

  uint64_t buffer;
  while (file.read(reinterpret_cast<char *>(&buffer), sizeof(buffer)))
	blocks.push_back(buffer);

  if (file.gcount() > 0) {
	buffer = 0;
	file.read(reinterpret_cast<char *>(&buffer), file.gcount());
	blocks.push_back(buffer);
  }

  file.close();
  return blocks;
}

void Utils::WriteBlocksToFile(const std::string &filename, std::string blocks) {
  std::ofstream file(filename, std::ios::binary);

  if (!file)
	std::cerr << "Error: Could not open file " << filename << std::endl;

  file.write(blocks.c_str(), blocks.size());
  file.close();
}