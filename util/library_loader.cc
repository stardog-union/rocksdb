//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#include "util/library_loader.h"

#include <dlfcn.h>

// link with -ldl

namespace rocksdb {

UnixLibraryLoader::UnixLibraryLoader(const char * library_name)
    : dl_handle_(nullptr) {

  if (nullptr != library_name && '\0' != *library_name) {
    dl_handle_ = dlopen(library_name, RTLD_NOW | RTLD_GLOBAL);

    is_valid_ = (nullptr != dl_handle_);

    if (!is_valid_) {
      last_error_msg_ = dlerror();
    }
  }
}


UnixLibraryLoader::~UnixLibraryLoader() {
  if (nullptr != dl_handle_ ) {
    int ret_val = dlclose(dl_handle_);
    dl_handle_ = nullptr;
    is_valid_ = false;

    if (0 != ret_val) {
      last_error_msg_ = dlerror();
    }
  }
}


void * UnixLibraryLoader::GetEntryPoint(const char * function_name) {
  void * ret_ptr = {nullptr};

  if (is_valid_) {
    ret_ptr = dlsym(dl_handle_, function_name);
    if (nullptr == ret_ptr) {
      last_error_msg_ = dlerror();
    }
  }

  return ret_ptr;
}

} // namespace rocksdb
