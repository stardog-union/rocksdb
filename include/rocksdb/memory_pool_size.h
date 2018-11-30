#pragma once

#include <memory>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include "memory_pool.h"

namespace rocksdb {

class MemoryPoolSize final {
 private:
  std::mutex mMutex{};

  std::unordered_map<char *, size_t> *mIndex;

  std::unordered_map<size_t, MemoryPool *> mPools{};

  MemoryPoolSize() : mIndex(new std::unordered_map<char *, size_t>()) {}

 public:
  MemoryPoolSize(MemoryPoolSize const &) = delete;
  MemoryPoolSize &operator=(MemoryPoolSize const &) = delete;

  ~MemoryPoolSize() {
    for (auto &entry : mPools) {
      delete entry.second;
    }
  }

  static std::shared_ptr<MemoryPoolSize> &instance() {
    static std::shared_ptr<MemoryPoolSize> s{new MemoryPoolSize};
    return s;
  }

  size_t getPoolingSIze(const size_t theBlockSize) {
    if (theBlockSize <= 1024) {
      return 1024;
    }

    if (theBlockSize <= 512 * 1024) {
      return 512 * 1024;
    }

    if (theBlockSize <= 1024 * 1024) {
      return 1024 * 1024;
    }

    if (theBlockSize <= 2 * 1024 * 1024) {
      return 2 * 1024 * 1024;
    }

    if (theBlockSize <= 4 * 1024 * 1024) {
      return 4 * 1024 * 1024;
    }

    if (theBlockSize <= 8 * 1024 * 1024) {
      return 8 * 1024 * 1024;
    }

    if (theBlockSize <= 16 * 1024 * 1024) {
      return 16 * 1024 * 1024;
    }

    if (theBlockSize <= 64 * 1024 * 1024) {
      return 64 * 1024 * 1024;
    }

    return theBlockSize;
  }

  char *allocate(const size_t theBlockSize) {
    std::lock_guard<std::mutex> lock{mMutex};
    size_t aPoolSize = getPoolingSIze(theBlockSize);

    if (mPools.find(aPoolSize) == mPools.end()) {
      auto *aMemoryBlockPool = new MemoryPool(aPoolSize);
      char *aPtr = aMemoryBlockPool->allocate();
      mPools.emplace(aPoolSize, aMemoryBlockPool);
      mIndex->emplace(aPtr, aPoolSize);
      return aPtr;
    } else {
      char *aPtr = mPools.at(aPoolSize)->allocate();
      mIndex->emplace(aPtr, aPoolSize);
      return aPtr;
    }
  }

  void release(char *thePtr) {
    std::lock_guard<std::mutex> lock{mMutex};

    if (mIndex->find(thePtr) == mIndex->end()) {
      delete[] thePtr;
      return;
    }

    size_t aPoolSize = mIndex->at(thePtr);

    if (mPools.find(aPoolSize) != mPools.end()) {
      mPools.at(aPoolSize)->release(thePtr);
      mIndex->erase(thePtr);
    } else {
      delete[] thePtr;
    }
  }
};  // namespace rocksdb
}  // namespace rocksdb