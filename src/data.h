#pragma once

#include <algorithm>
#include <cassert>
#include <iterator>
#include <vector>

class Data {
public:
  static constexpr uint32_t ZipHeaderLength = 12;

  Data(const std::vector<uint8_t>& cipherSnippet, const std::vector<uint8_t>& plainSnippet, const std::vector<uint8_t>& zipHeader) {
    assert(cipherSnippet.size() == plainSnippet.size());
    mEncryptedZipHeader = zipHeader;
    assert(mEncryptedZipHeader.size() == ZipHeaderLength);
    mCipherText = cipherSnippet;
    mPlainText = plainSnippet;
    std::transform(
      plainSnippet.begin(),
      plainSnippet.end(),
      cipherSnippet.begin(),
      std::back_inserter(mKey3Sequence),
      [](const uint8_t& L, const uint8_t& R) { return L ^ R; }
    );
  }
  std::vector<uint8_t> mEncryptedZipHeader;
  std::vector<uint8_t> mCipherText;
  std::vector<uint8_t> mPlainText;
  std::vector<uint8_t> mKey3Sequence;
};

