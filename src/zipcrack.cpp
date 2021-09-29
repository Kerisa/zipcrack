
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "pkcipher.h"
#include "reducekey.h"
#include "data.h"
#include "explorer.h"

using namespace std;

int main(int argc, char** argv) {
  if (argc != 3) {
    cout << "usage: zipcrack.exe <Encrypted_zip_data> <plain_file_data>\n";
    return 1;
  }

  std::ifstream zipFile(argv[1], std::ios::binary);
  zipFile.seekg(0, ios::end);
  vector<uint8_t> zipData(static_cast<size_t>(zipFile.tellg()));
  zipFile.seekg(0, ios::beg);
  zipFile.read((char*)zipData.data(), zipData.size());
  zipFile.close();

  std::ifstream plainFile(argv[2], std::ios::binary);
  plainFile.seekg(0, ios::end);
  vector<uint8_t> plainData(static_cast<size_t>(plainFile.tellg()));
  plainFile.seekg(0, ios::beg);
  plainFile.read((char*)plainData.data(), plainData.size());
  plainFile.close();

  assert(zipData.size() > Data::ZipHeaderLength);
  Data d({ zipData.begin() + Data::ZipHeaderLength, zipData.end() }, plainData, { zipData.begin(), zipData.begin() + Data::ZipHeaderLength });
  ReduceKey reduce(d);
  reduce.Reduce();

  // 因为只依靠 reduce key2 的范围并不能唯一确定出三个 key，
  // 所以使用 key3 序列的前面一部分来缩小 key2 的候选数量，
  // 然后用剩下的 key3 序列进行深搜，最终确定出一个可行的 key 组合

  KeyExplorer exp(d);
  for (uint32_t k2 : reduce.mPossibleKey2) {
    if (exp.SearchKeyLists(k2)) {
      auto k = exp.GetKeys();
      cout << "found key: " << k[0] << " " << k[1] << " " << k[2] << "\n";
      break;
    }
  }

  cout << "search finished.\n";
  return 0;
}
