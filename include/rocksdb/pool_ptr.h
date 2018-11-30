#pragma once
#include <memory>
#include "memory_pool_size.h"

namespace rocksdb {

struct PoolDeleter {
  void operator()(char *ptr) {
    if (ptr != nullptr) {
      MemoryPoolSize::instance()->release(ptr);
    }
  }
};

class pool_ptr : public std::unique_ptr<char[], PoolDeleter> {};
}  // namespace rocksdb