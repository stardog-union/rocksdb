#pragma once

#include <iostream>
#include <stack>
#include <unordered_map>
#include <vector>

namespace rocksdb {

class MemoryPool final {
 private:
  size_t mBlockSize;

  std::stack<size_t> *mAvailableBlocks;

  std::unordered_map<char *, size_t> *mIndex;

  std::vector<char *> *mMemoryPool;

  void createNewBlocks() {
    char *aData = new char[mBlockSize];
    mMemoryPool->push_back(aData);
    size_t aIndex = mMemoryPool->size();
    mAvailableBlocks->emplace(aIndex - 1);
    mIndex->emplace(aData, aIndex - 1);
  }

 public:
  explicit MemoryPool(const size_t theBlockSize) : mBlockSize(theBlockSize) {
    mMemoryPool = new std::vector<char *>();
    mAvailableBlocks = new std::stack<size_t>();
    mIndex = new std::unordered_map<char *, size_t>();
  }

  ~MemoryPool() {
    for (char *ptr : *(mMemoryPool)) {
      delete[] ptr;
    }

    delete mIndex;
    delete mMemoryPool;
    delete mAvailableBlocks;
  }

  char *allocate() {
    if (mAvailableBlocks->empty()) {
      createNewBlocks();
    }

    size_t aAvailableIndex = mAvailableBlocks->top();
    mAvailableBlocks->pop();
    char *aPtr = mMemoryPool->at(aAvailableIndex);
    return aPtr;
  }

  void release(char *thePtr) {
    if (mIndex->find(thePtr) == mIndex->end()) {
      delete[] thePtr;
      return;
    }

    mAvailableBlocks->push(mIndex->at(thePtr));
  }
};
}  // namespace rocksdb