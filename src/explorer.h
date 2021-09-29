#pragma once
#include <array>
#include <vector>

class Data;
class KeyExplorer {
public:
  KeyExplorer(const Data& d);

  bool SearchKeyLists(uint32_t k2_2_32);
  std::array<uint32_t, 3> GetKeys();

private:
  static constexpr uint32_t SEARCH_SPACE = 12;

  bool pSearchKey0Lists();
  bool pSearchKey1Lists(int index);
  bool pSearchKey2Lists(int index);

private:
  std::vector<uint32_t> mKey0List;
  std::vector<uint32_t> mKey1List;
  std::vector<uint32_t> mKey2List;

  const Data& mDataRef;
};