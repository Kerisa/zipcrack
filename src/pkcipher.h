#pragma once

#include <array>
#include <string>
#include <vector>

class PKCipher {

public:
  static constexpr uint32_t MUL    = 0x8088405;
  static constexpr uint32_t MULINV = 0xd94fa8cd;  // 0x8088405 µÄ³Ë·¨ÄæÔª

public:
  PKCipher(uint32_t _k0 = 0x12345678, uint32_t _k1 = 0x23456789, uint32_t _k2 = 0x34567890) : k0(_k0), k1(_k1), k2(_k2) {}
  PKCipher(std::string pwd);
  void Encrypt(std::vector<uint8_t>& data);
  void Decrypt(std::vector<uint8_t>& data);

  void UpdateKeys(uint8_t c);
  void UpdateKeysBackward(uint8_t c);
  uint8_t GetK3();

  std::array<uint32_t, 3> GetKeys() { return { k0, k1, k2 }; }

private:
  uint32_t k0{ 0x12345678 };
  uint32_t k1{ 0x23456789 };
  uint32_t k2{ 0x34567890 };
};