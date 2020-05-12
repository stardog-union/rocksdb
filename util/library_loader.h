// Copyright (c) 2011-present, Facebook, Inc. All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#pragma once

#include <string>

namespace rocksdb {

// Base class / interface
//  expectation is to derive one class for unux and one for Windows
//
class LibraryLoader {
 public:
  LibraryLoader() : is_valid_(false) {};
  virtual ~LibraryLoader() = default;

  bool IsValid() const {return is_valid_;}

  virtual void * GetEntryPoint(const char * function_name) = 0;

 protected:
  bool is_valid_;
};


class UnixLibraryLoader : public LibraryLoader {
 public:
  UnixLibraryLoader() = delete;

  UnixLibraryLoader(const char * library_name);

  virtual ~UnixLibraryLoader();

  virtual void * GetEntryPoint(const char * function_name) override;

protected:
  void * dl_handle_;
  std::string last_error_msg_;
};

}  // namespace rocksdb
