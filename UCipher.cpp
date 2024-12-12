#include "UCipher.h"

std::vector<uint32_t> UCipher::GenerateKeys(const uint8_t &key_length_bits) {
  std::vector<uint32_t> keys;
  keys.reserve(10);
  std::mt19937 rng(std::random_device{}());
  std::uniform_int_distribution<uint32_t> dist(0, (1LL << key_length_bits) - 1);
  std::chrono::duration<double> duration{};

  for (size_t i = 0; i < 10; ++i)
	keys.push_back(dist(rng));
  return keys;
}

uint8_t UCipher::Rotate(uint8_t a, uint8_t b, uint8_t x, uint8_t pos) {
  uint8_t tmp = a + b + x;
  if (pos > 0)
	return (tmp << pos) | (tmp >> (8 - pos));
  else
	return (tmp >> -pos) | (tmp << (8 + pos));
}

uint32_t UCipher::RoundFunction(uint32_t msg, uint32_t key) {
  msg ^= key;

  uint8_t x[4], y[4];
  for (int i = 0; i < 4; i++) {
	x[3 - i] = static_cast<uint8_t>(msg & 0xFF);
	msg >>= 8;
  }

  y[0] = x[0];
  y[1] = y[0] ^ x[1];
  y[2] = y[1] ^ x[2];
  y[3] = y[2] ^ x[3];

  y[1] = Rotate(y[1], y[2], 4, 2);
  y[2] = Rotate(y[2], y[3], 1, 1);
  y[3] = Rotate(y[3], y[2], 3, 3);

  y[2] ^= y[3];
  y[1] ^= y[2];
  y[0] ^= y[1];

  y[2] = Rotate(y[1], y[2], 2, 1);
  y[0] = Rotate(y[0], y[1], 1, 3);

  uint32_t output = 0;
  for (int i = 0; i < 4; i++)
	output |= (uint32_t(y[i]) << (8 * (3 - i)));

  return output;
}

uint64_t UCipher::Encrypt(uint64_t msg) {
  auto [left, right] = Utils::SplitBlock(msg);

  left ^= keys_[4];
  right ^= keys_[5];

  auto round_1_left = left ^ right ^ keys_[6];
  auto round_1_right = left ^ RoundFunction(round_1_left, keys_[0]);

  auto round_2_left = round_1_right ^ keys_[7];
  auto round_2_right = round_1_left ^ RoundFunction(round_1_right, keys_[1]);

  auto round_3_left = round_2_right ^ keys_[8];
  auto round_3_right = round_2_left ^ RoundFunction(round_2_right, keys_[2]);

  auto round_4_left = round_3_left ^ RoundFunction(round_3_right, keys_[3]);
  auto round_4_right = round_4_left ^ round_3_right ^ keys_[9];

  return Utils::MergeBlock(round_4_left, round_4_right);
}

uint64_t UCipher::Decrypt(uint64_t msg) {
  auto [left, right] = Utils::SplitBlock(msg);

  auto round_3_right = left ^ right ^ keys_[9];
  auto round_3_left = left ^ RoundFunction(round_3_right, keys_[3]);

  auto round_2_right = round_3_left ^ keys_[8];
  auto round_2_left = round_3_right ^ RoundFunction(round_2_right, keys_[2]);

  auto round_1_right = round_2_left ^ keys_[7];
  auto round_1_left = round_2_right ^ RoundFunction(round_1_right, keys_[1]);

  left = round_1_right ^ RoundFunction(round_1_left, keys_[0]);
  right = left ^ round_1_left ^ keys_[6];

  left = left ^ keys_[4];
  right = right ^ keys_[5];

  return Utils::MergeBlock(left, right);
}
