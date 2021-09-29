#pragma once


#include <cstdint>

namespace crc
{
  constexpr uint8_t msb(uint32_t v);

  constexpr uint8_t lsb(uint32_t v);

  uint32_t Crc32(uint32_t pval, uint8_t b);

  uint32_t Crc32Inv(uint32_t crc, uint8_t b);
};
