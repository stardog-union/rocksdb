// Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#include <cstdio>
#include <string>
#include <iostream>
#include <include/rocksdb/slice_transform.h>
#include <include/rocksdb/table.h>
#include "rocksdb/db.h"
#include <rocksdb/filter_policy.h>

using namespace std;
using namespace rocksdb;
using namespace std::chrono;

#include <thread>
#include <cinttypes>

std::string kDBPath = "/repos/rocksdata";

template<typename T>
T swap_endian(T u) {
    static_assert(CHAR_BIT == 8, "CHAR_BIT != 8");

    union {
        T u;
        unsigned char u8[sizeof(T)];
    } source, dest;

    source.u = u;

    for (size_t k = 0; k < sizeof(T); k++)
        dest.u8[k] = source.u8[sizeof(T) - k - 1];

    return dest.u;
}

rocksdb::TableFactory *makeDictionaryTableFactory() {
    auto block_opts = rocksdb::BlockBasedTableOptions{};
    block_opts.checksum = ChecksumType::kCRC32c;
    block_opts.index_type = BlockBasedTableOptions::kHashSearch;
    block_opts.filter_policy.reset(NewBloomFilterPolicy(10, false));
    block_opts.block_cache =
            NewLRUCache(static_cast<size_t>(1024 * 1024 * 1024));
    block_opts.cache_index_and_filter_blocks = true;
    block_opts.cache_index_and_filter_blocks_with_high_priority = block_opts.cache_index_and_filter_blocks;

    auto *pPolicy = rocksdb::NewBloomFilterPolicy(10, false);
    auto filter_ptr = std::shared_ptr<const rocksdb::FilterPolicy>(pPolicy);
    block_opts.filter_policy = filter_ptr;

    return rocksdb::NewBlockBasedTableFactory(block_opts);
}

int main() {
    system("rm -rf /repos/rocksdata/*");

    DB *db;
    Options options;
    // Optimize RocksDB. This is the easiest way to get RocksDB to perform well
    //options.IncreaseParallelism();
    //options.OptimizeLevelStyleCompaction();
    // create the DB if it's not already present
    options.create_if_missing = true;
    options.compression = CompressionType::kNoCompression;
    options.statistics = rocksdb::CreateDBStatistics();
    // open DB
    Status s = DB::Open(options, kDBPath, &db);

    if (!s.ok()) {
        std::cout << s.ToString();
    }

    assert(s.ok());

    ColumnFamilyOptions cf_options{};

    cf_options.table_factory.reset(makeDictionaryTableFactory());
    cf_options.prefix_extractor.reset(rocksdb::NewNoopTransform());
    cf_options.memtable_prefix_bloom_size_ratio = 0.02;

    std::string name("Name");
    ColumnFamilyHandle *cf;
    Status status = db->CreateColumnFamily(cf_options, name, &cf);

    assert(s.ok());

    u_int64_t *buffer = new u_int64_t[4];
    char *pointer = reinterpret_cast<char *>(buffer);
    WriteBatch writeBatch{};
    u_int64_t max = 10000000;

    Slice key(pointer, 32);
    Slice value(reinterpret_cast<char *>(&max), 8);


    u_int64_t *buffer1 = new u_int64_t[4];
    char *pointer1 = reinterpret_cast<char *>(buffer1);
    Slice key1(pointer1, 32);

    for (u_int64_t i = 0; i < 1000000000; i++) {
        *(buffer) = swap_endian(i);
        *(buffer + 1) = i + 1;
        *(buffer + 2) = i + 2;
        *(buffer + 3) = i + 3;

        writeBatch.Put(cf, key, value);

        if (i % 1000 == 0) {
            Status s1 = db->Write(WriteOptions(), &writeBatch);
            assert(s1.ok());
            writeBatch.Clear();
        }

        if (i % 10000000 == 0) {
            std::string valuee;
            // get value
            uint64_t start = (uint64_t) std::chrono::duration_cast<std::chrono::nanoseconds>(
                    system_clock::now().time_since_epoch()).count();

            u_int64_t k = i / 2;
            *(buffer1) = swap_endian(k);
            *(buffer1 + 1) = k + 1;
            *(buffer1 + 2) = k + 2;
            *(buffer1 + 3) = k + 3;

            s = db->Get(ReadOptions(), cf, key1, &valuee);

            uint64_t end = (uint64_t) std::chrono::duration_cast<std::chrono::nanoseconds>(
                    system_clock::now().time_since_epoch()).count();
            u_int64_t delta = end - start;

            printf("%" PRIu64 "\n", delta);
            db->Flush(FlushOptions(), cf);
        }
    }

    db->DestroyColumnFamilyHandle(cf);
    delete db;
    return 0;
}
