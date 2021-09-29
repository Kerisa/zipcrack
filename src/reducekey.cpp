
#include <algorithm>
#include <array>
#include <cassert>
#include <iterator>
#include <mutex>
#include <set>
#include "crc32.h"
#include "reducekey.h"
#include "data.h"

ReduceKey::ReduceKey(const Data& d)
  : mDataRef(d) {
  // 由最后一个 key3 初始化所有 key2 的可能值, 2^22
  mPossibleKey2 = pGeneratePossibleKey2(d.mKey3Sequence.back());
}

void ReduceKey::Reduce() {

  for (int i = mDataRef.mKey3Sequence.size() - 1; i >= 12; --i) {

    std::vector<uint32_t> possibleKey2_im2_2_16 = GeneratePossibleKey2_2_16(mDataRef.mKey3Sequence[i - 1]);
    std::set<uint32_t> possibleKey2_im2;
    for (uint32_t k2_im1 : mPossibleKey2) {
      uint32_t k2_im1_10_32 = crc::Crc32Inv(k2_im1, 0) & 0xfffffc00;

      // 根据公式
      // Key2{n-1} = crcinv(Key2{n} ^ MSB(Key1{n-1}))
      //           = (Key2{n} << 8) ^ crcinvtable(MSB(Key2{n})) ^ MSB(Key1{n})
      // 其中 crcinv(MSB(Key2{n})) 为“确定值”（遍历高 16 位时），
      // 而 MSB(Key1{n}) 的 [8,32) 为 0
      // Key2{n} 中 [2, 16) 位可以通过 key3 确定，高 16 位做遍历，然后左移了 8 位就变成 [10, 32) “已知”
      // Key2{n-1} 的 [2, 16) 位也通过 key3 确定，所以 {n} 和 {n-1} 有了相同的 [10, 16) 位

      for (uint32_t p : possibleKey2_im2_2_16) {
        if ((k2_im1_10_32 & 0xfc00) == (p & 0xfc00)) {    // 比较 [10, 16) 部分是否相同
          possibleKey2_im2.insert(k2_im1_10_32 | p);      // 用集合以便去重
        }
      }
    }

    if (possibleKey2_im2.size() < mPossibleKey2.size()) {
      mPossibleKey2.clear();
      std::copy(possibleKey2_im2.begin(), possibleKey2_im2.end(), std::back_inserter(mPossibleKey2));
      possibleKey2_im2.clear();
    }
  }
}

std::vector<uint32_t> ReduceKey::pGeneratePossibleKey2(uint8_t key3) {
  std::vector<uint32_t> k2_2_16 = GeneratePossibleKey2_2_16(key3);
  std::set<uint32_t> veck2;
  for (int i : k2_2_16) {
    for (uint32_t m = 0; m < (1 << 16); ++m) {
      veck2.insert((m << 16) | i);
    }
  }
  return std::vector<uint32_t>(veck2.begin(), veck2.end());
}

namespace {
  std::once_flag flag1;
  std::array<std::vector<uint32_t>, 256> map_key2_2_16;
}

const std::vector<uint32_t>& ReduceKey::GeneratePossibleKey2_2_16(uint8_t key3) {
  std::call_once(flag1, []() {
    for (int i = 0; i < (1 << 14); ++i) {
      uint16_t tmp = (i << 2) | 3;
      uint8_t k3 = crc::lsb((tmp * (tmp ^ 1)) >> 8);
      map_key2_2_16[k3].push_back(i << 2);
    }
  });

  return map_key2_2_16[key3];
}
