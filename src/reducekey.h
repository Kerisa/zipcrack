#pragma once

#include <vector>

class Data;
class ReduceKey {
public:
  ReduceKey(const Data& d);

  void Reduce();

  static const std::vector<uint32_t>& GeneratePossibleKey2_2_16(uint8_t key3);

private:
  std::vector<uint32_t> pGeneratePossibleKey2(uint8_t key3);

public:
  const Data&           mDataRef;
  std::vector<uint32_t> mPossibleKey2;
};