#include "DiffCryptAnalysis.h"
#include <random>
#include <iostream>

std::pair<std::vector<std::pair<uint64_t, uint64_t>>, std::vector<std::pair<uint64_t, uint64_t>>>
DiffCryptAnalysis::GenerateCiphertexts(uint64_t diff) {
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX);

  std::vector<std::pair<uint64_t, uint64_t>> texts(texts_number_);
  std::vector<std::pair<uint64_t, uint64_t>> ciphertexts(texts_number_);

  for (int i = 0; i < texts_number_; i++) {
	texts[i].first = dist(gen);
	texts[i].second = texts[i].first ^ diff;

	ciphertexts[i].first = cipher_.Encrypt(texts[i].first);
	ciphertexts[i].second = cipher_.Encrypt(texts[i].second);
  }

  return {texts, ciphertexts};
}

void DiffCryptAnalysis::DecryptLastOperation(std::vector<std::pair<uint64_t, uint64_t>> &ciphertexts) const {
  for (int i = 0; i < texts_number_; i++) {
	auto [cipher_left_0, cipher_right_0] = Utils::SplitBlock(ciphertexts[i].first);
	auto [cipher_left_1, cipher_right_1] = Utils::SplitBlock(ciphertexts[i].second);

	ciphertexts[i].first = Utils::MergeBlock(cipher_left_0, cipher_right_0 ^ cipher_left_0);
	ciphertexts[i].second = Utils::MergeBlock(cipher_left_1, cipher_right_1 ^ cipher_left_1);
  }
}

[[nodiscard]] uint32_t DiffCryptAnalysis::CrackHighestRound(uint32_t differential,
															std::vector<std::pair<uint64_t,
																				  uint64_t>> &ciphertexts) const {
  std::cout << "  In progress...\n";

  for (uint32_t key_to_check = 0x00000000; key_to_check <= 0xFFFFFFFF; key_to_check++) {
	uint32_t score = 0;

	for (uint32_t i = 0; i < texts_number_; i++) {
	  auto [cipher_left_0, cipher_right_0] = Utils::SplitBlock(ciphertexts[i].first);
	  auto [cipher_left_1, cipher_right_1] = Utils::SplitBlock(ciphertexts[i].second);

	  uint32_t cipher_left = cipher_left_0 ^ cipher_left_1;
	  uint32_t actual = cipher_left ^ differential;

	  uint32_t found =
		  UCipher::RoundFunction(cipher_right_0, key_to_check) ^
			  UCipher::RoundFunction(cipher_right_1, key_to_check);

	  if (actual == found) ++score;
	  else break;
	}

	if (score == texts_number_) {
	  std::cout << "  Found key : 0x" << std::hex << key_to_check << std::dec << std::endl;
	  return key_to_check;
	}
  }

  std::cout << "  FAILED" << std::endl;
//  throw std::exception();
  return 0;
}

void DiffCryptAnalysis::DecryptHighestRound(uint32_t cracked_key,
											std::vector<std::pair<uint64_t, uint64_t>> &ciphertexts) const {
  for (int i = 0; i < texts_number_; i++) {
	uint64_t cipher_left_0 = ciphertexts[i].first & 0xFFFFFFFF;
	uint64_t cipher_left_1 = ciphertexts[i].second & 0xFFFFFFFF;

	uint64_t cipher_right_0 = UCipher::RoundFunction(cipher_left_0, cracked_key) ^ (ciphertexts[i].first >> 32);
	uint64_t cipher_right_1 = UCipher::RoundFunction(cipher_left_1, cracked_key) ^ (ciphertexts[i].second >> 32);

	ciphertexts[i].first = Utils::MergeBlock(cipher_left_0, cipher_right_0);
	ciphertexts[i].second = Utils::MergeBlock(cipher_left_1, cipher_right_1);
  }
}

std::vector<uint32_t> DiffCryptAnalysis::CrackCipher() {
  std::vector<uint32_t> found_keys(10, 0);
  std::vector<std::pair<uint64_t, uint64_t>> ciphertexts;
  std::vector<std::pair<uint64_t, uint64_t>> texts;

  for (int i = 3; i > 0; --i) {
	std::cout << "ROUND " << i + 1 << ": \n";
	std::tie(texts, ciphertexts) = GenerateCiphertexts(diffs_[i - 1]);
	DecryptLastOperation(ciphertexts);
	for (int j = 3; j > i; --j)
	  DecryptHighestRound(found_keys[j], ciphertexts);
	found_keys[i] = CrackHighestRound(0x4000000, ciphertexts);
  }

  std::cout << "ROUND 1:\n";
  DecryptHighestRound(found_keys[1], ciphertexts);
  std::cout << "  In progress...\n";

  for (uint32_t key_to_check = 0; key_to_check < 0xFFFFFFFF; key_to_check++) {
	uint32_t tmp_k_4 = 0, tmp_k_5 = 0;

	bool valid = true;
	for (int i = 0; i < texts_number_; i++) {
	  auto [cipher_left_0, cipher_right_0] = Utils::SplitBlock(ciphertexts[i].first);
	  auto [plain_left_0, plain_right_0] = Utils::SplitBlock(texts[i].first);

	  uint32_t new_diff = UCipher::RoundFunction(cipher_right_0, key_to_check) ^ cipher_left_0;
	  if (tmp_k_4 == 0) {
		tmp_k_4 = new_diff ^ plain_left_0;
		tmp_k_5 = new_diff ^ cipher_right_0 ^ plain_right_0;
	  } else if ((new_diff ^ plain_left_0) != tmp_k_4 || (new_diff ^ cipher_right_0 ^ plain_right_0) != tmp_k_5) {
		valid = false;
		break;
	  }
	}

	if (valid && tmp_k_4 != 0) {
	  found_keys[0] = key_to_check;
	  found_keys[4] = tmp_k_4;
	  found_keys[5] = tmp_k_5;
	  break;
	}
  }
  std::cout << "  Found keys : K0 = 0x" << std::hex << found_keys[0] << ", K4 = 0x"
			<< found_keys[4] << ", K5 = 0x"
			<< found_keys[5] << std::dec << std::endl;

  return found_keys;
}