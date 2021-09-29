
#include "crc32.h"
#include "data.h"
#include "explorer.h"
#include "reducekey.h"
#include "PKCipher.h"

KeyExplorer::KeyExplorer(const Data& d) 
  : mDataRef(d) {
  mKey0List.resize(SEARCH_SPACE);
  mKey1List.resize(SEARCH_SPACE);
  mKey2List.resize(SEARCH_SPACE);
}

bool KeyExplorer::SearchKeyLists(uint32_t k2_2_32) {
  mKey2List[SEARCH_SPACE-1] = k2_2_32;
  return pSearchKey2Lists(SEARCH_SPACE - 1);
}

bool KeyExplorer::pSearchKey2Lists(int index) {
  if (index > 0) {
    uint32_t k2_im1_10_32 = crc::Crc32Inv(mKey2List[index], 0) & 0xfffffc00;
    auto vec_k2_im1_2_16 = ReduceKey::GeneratePossibleKey2_2_16(mDataRef.mKey3Sequence[index - 1]);
    for (uint32_t k2_im1_2_16 : vec_k2_im1_2_16) {
      mKey2List[index - 1] = k2_im1_10_32 | k2_im1_2_16;
      // 现在知道了 Key2{n-1} 的所有位，根据公式有
      // Key2{n-1} = crcinv(Key2{n} ^ MSB(Key1{n-1}))
      //           = (Key2{n} << 8) ^ crcinvtable(MSB(Key2{n})) ^ MSB(Key1{n})
      // 但是 Key2{n} 少了两位，这两位反映在 Key2{n-1} 的 8，9 位上，
      // 所以 crcinv(Key2{n} ^ MSB(Key1{n-1})) 和 Key2{n-1} 异或的差异就是这两个位
      mKey2List[index] &= ~0x3;
      mKey2List[index] |= (mKey2List[index - 1] ^ crc::Crc32Inv(mKey2List[index], 0)) >> 8;

      // 所以这时 MSB(Key1{n-1}) 也确定了，不过 Key2{n-1} 的最低两位还没确定，所以放到下一轮中计算
      if (index < SEARCH_SPACE - 1)
        mKey1List[index + 1] = (mKey2List[index] ^ crc::Crc32Inv(mKey2List[index + 1], 0)) << 24;

      if (pSearchKey2Lists(index - 1))
        return true;
    }

    return false;
  }
  else {
    // key2 搜完了，接着搜 key1
    // 根据 key 的更新公式
    //    Key1{i+1} = ((Key1{i} + LSB(Key0{i+1})) * 134775813 + 1) & 0xffffffff
    // 可以得到
    //    Key1{i} + LSB(Key0{i+1}) = (Key1{i+1} - 1) / 134775813
    // 又因为 LSB(Key0{i+1}) 只有一字节，范围是 [0, 255]，所以对我们猜测 Key1 的 [8,24) 位几乎没有影响
    // 公式变为 Key1{i} = (Key1{i+1} - 1) / 134775813
    for (uint32_t k1_0_24 = 0; k1_0_24 < (1 << 24); ++k1_0_24) {
      uint32_t R = (((mKey1List[11] & 0xff000000) | k1_0_24) - 1) * PKCipher::MULINV;
      if (crc::msb(mKey1List[10]) == crc::msb(R) ||
        (crc::msb(mKey1List[10]) + 1) % 256 == crc::msb(R) ||
        (crc::msb(mKey1List[10]) - 1) % 256 == crc::msb(R)) {
        mKey1List[11] = k1_0_24 | (mKey1List[11] & 0xff000000);
        if (pSearchKey1Lists(11))
          return true;
      }
    }
    return false;
  }
}

bool KeyExplorer::pSearchKey1Lists(int index) {
  if (index > 3) { // 根据论文描述，只能搜索到 key1{4} 为止
    for (uint32_t k0_0_8 = 0; k0_0_8 < 0x100; ++k0_0_8) {
      uint32_t k1_im1 = (mKey1List[index] - 1) * PKCipher::MULINV - k0_0_8;
      if (crc::msb(mKey1List[index - 1]) == crc::msb(k1_im1) ||
        (crc::msb(mKey1List[index - 1]) + 1) % 256 == crc::msb(k1_im1) ||
        (crc::msb(mKey1List[index - 1]) - 1) % 256 == crc::msb(k1_im1)) {
        mKey1List[index - 1] = (mKey1List[index - 1] & 0xff000000) | (k1_im1 & 0x00ffffff);
        mKey0List[index] = k0_0_8;
        if (pSearchKey1Lists(index - 1))
          return true;
      }
    }
    return false;
  }
  else
    return pSearchKey0Lists();
}

bool KeyExplorer::pSearchKey0Lists() {
  // compute X7
  for (int i = 5; i <= 7; i++)
    mKey0List[i] = (crc::Crc32(mKey0List[i - 1], mDataRef.mPlainText[i - 1])
      & 0xffffff00)
    | crc::lsb(mKey0List[i]); // 使用原有的 LSB

  uint32_t x = mKey0List[7];

  // compare 4 LSB(Xi) obtained from plaintext with those from the X-list
  for (int i = 8; i <= 11; i++) {
    x = crc::Crc32(x, mDataRef.mPlainText[i - 1]);
    if (crc::lsb(x) != crc::lsb(mKey0List[i]))
      return false;
  }

  // compute X3
  x = mKey0List[7];
  for (int i = 6; i >= 3; i--)
    x = crc::Crc32Inv(x, mDataRef.mPlainText[i]);

  // check that X3 fits with Y1[26,32)
  // 原本从 key2 逆推 key1 可以得到 key1 的 MSB，但是逆推出 key2 时有个按位与 3 的操作，所以这里再扣掉两个位，变成 [26,32)
  uint32_t y1_26_32 = ((crc::Crc32Inv(mKey2List[1], 0) ^ mKey2List[0]) << 24) & 0xfc000000;
  // key1 逆推两次
  uint32_t diff = ((mKey1List[3] - 1) * PKCipher::MULINV - crc::lsb(x) - 1) * PKCipher::MULINV - y1_26_32;
  if (diff > (0x03ffffff + 0xff))   // 从两个方向逼近的结果，误差要在 2^27-1 之间，公式里还有个 LSB(Key0)，所以再加上 0xff
    return false;

  return true;
}

std::array<uint32_t, 3> KeyExplorer::GetKeys() {
  PKCipher cipher(mKey0List[7], mKey1List[7], mKey2List[7]);

  // get the keys associated with the initial state
  for (int i = 6; i >= 0; --i) {
    cipher.UpdateKeysBackward(mDataRef.mCipherText[i]);
  }

  for (int i = mDataRef.mEncryptedZipHeader.size() - 1; i >= 0; --i) {
    cipher.UpdateKeysBackward(mDataRef.mEncryptedZipHeader[i]);
  }

  return cipher.GetKeys();
}
