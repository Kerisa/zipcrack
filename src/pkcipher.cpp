
#include "pkcipher.h"
#include "crc32.h"

void PKCipher::Encrypt(std::vector<uint8_t>& data) {
  for (uint8_t& p : data) {
    uint8_t c = p ^ GetK3();
    UpdateKeys(p);
    p = c;
  }
}

void PKCipher::Decrypt(std::vector<uint8_t>& data) {
  for (uint8_t& c : data) {
    uint8_t p = c ^ GetK3();
    UpdateKeys(p);
    c = p;
  }
}

PKCipher::PKCipher(std::string pwd) {
  for (auto c : pwd)
    UpdateKeys(c);
}

void PKCipher::UpdateKeys(uint8_t c) {
  k0 = crc::Crc32(k0, c);
  k1 = (k1 + crc::lsb(k0)) * MUL + 1;
  k2 = crc::Crc32(k2, crc::msb(k1));
}

void PKCipher::UpdateKeysBackward(uint8_t c)
{
  k2 = crc::Crc32Inv(k2, crc::msb(k1));
  k1 = (k1 - 1) * MULINV - crc::lsb(k0);
  uint32_t tmp = k2 | 3;
  k0 = crc::Crc32Inv(k0, c ^ crc::lsb(tmp * (tmp ^ 1) >> 8));
}

uint8_t PKCipher::GetK3() {
  uint16_t tmp = k2 | 3;
  return crc::lsb((tmp * (tmp ^ 1)) >> 8);
}
