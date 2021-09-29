
#include <array>
#include <mutex>
#include "crc32.h"

namespace crc
{

  std::array<uint32_t, 256> CrcTable;
  std::array<uint32_t, 256> CrcInvTable;

  std::once_flag InitTableFlag;

  constexpr uint8_t msb(uint32_t v) {
    return v >> 24;
  }

  constexpr uint8_t lsb(uint32_t v) {
    return v;
  }

  void InitTable() {
    for (int b = 0; b < 256; ++b) {
      uint32_t crc = b;
      for (int i = 0; i < 8; ++i) {
        if (crc & 1)
          crc = crc >> 1 ^ 0xedb88320;
        else
          crc = crc >> 1;
      }
      CrcTable[b] = crc;
      CrcInvTable[msb(crc)] = crc << 8 ^ b;
    }
  }

  uint32_t Crc32(uint32_t pval, uint8_t b)
  {
    std::call_once(InitTableFlag, InitTable);
    return pval >> 8 ^ CrcTable[lsb(pval) ^ b];
  }

  uint32_t Crc32Inv(uint32_t crc, uint8_t b)
  {
    std::call_once(InitTableFlag, InitTable);
    return crc << 8 ^ CrcInvTable[msb(crc)] ^ b;
  }

}
