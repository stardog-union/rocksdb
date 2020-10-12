#include <string>
#include <vector>
#include "rocksdb/db.h"
#include "rocksdb/options.h"
#include "db/log_reader.h"
#include "db/log_writer.h"
#include "db/version_edit.h"
#include "util/file_reader_writer.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <util/stderr_logger.h>

using namespace rocksdb;

#define DEBUG 1

#define OK(rc) if (!rc.ok()) { \
  fprintf(stderr, "Failed to ```" #rc "```: %s", &rc.ToString()[0]); \
  exit(1); \
}

void create_amgen_drop_records();

std::shared_ptr<Logger> logger = std::make_shared<StderrLogger>(InfoLogLevel::DEBUG_LEVEL);

/*
 * Dump the MANIFEST (sequence of VersionEdit objects)
 */
void dump_log(const char *manifest_file_name) {
    EnvOptions options;
    Env *env = Env::Default();

    std::unique_ptr<SequentialFile> rfile;
    OK(env->NewSequentialFile(manifest_file_name, &rfile, options));

    std::unique_ptr<SequentialFileReader> file_reader(new SequentialFileReader(std::move(rfile),
                                                                               manifest_file_name));

    int log_number = 1234; // TODO: need to compute this from the file name? or accept in argv
    log::Reader log_reader(logger,
                           std::move(file_reader), nullptr, true, log_number, false);

    Slice record;
    std::string scratch;
    while (log_reader.ReadRecord(&record, &scratch)) {
        VersionEdit edit;
        OK(edit.DecodeFrom(record));
        printf("%s", &edit.DebugJSON(0, true)[0]);
    }
}

Status append_record(log::Writer &writer, VersionEdit &record) {
    std::string buf;
    record.EncodeTo(&buf);

    if (DEBUG) {
        printf("Record contents: ");
        for (int i = 0; i < buf.length(); ++i) {
            printf("%02x ", (unsigned char) buf[i]);
        }
        printf("\n");
    }

    return writer.AddRecord(buf);
}

Status add_file_delete(log::Writer &writer, int level, uint32_t cf, uint64_t file_num) {
    VersionEdit e = VersionEdit();
    e.DeleteFile(level, file_num);
    e.SetColumnFamily(cf);
    return append_record(writer, e);
}

void do_append() {
    EnvOptions options;
    Env *env = Env::Default();
    std::unique_ptr<WritableFile> wfile;
    const char *filename = "test_log";
    OK(env->NewWritableFile(filename, &wfile, options));

    std::unique_ptr<WritableFileWriter> file_writer(new WritableFileWriter(
            std::move(wfile),
            (std::string &) filename,
            options));

    log::Writer writer(std::move(file_writer), 999999999, false);

    OK(add_file_delete(writer, 0, 3, 44691));
    OK(add_file_delete(writer, 1, 21, 44704));
    OK(add_file_delete(writer, 1, 21, 44705));
    OK(add_file_delete(writer, 1, 22, 44706));
    OK(add_file_delete(writer, 1, 22, 44707));
    OK(add_file_delete(writer, 0, 336, 44695));
    OK(add_file_delete(writer, 1, 337, 44709));
    OK(add_file_delete(writer, 1, 338, 44710));
    OK(add_file_delete(writer, 0, 340, 44698));
    OK(add_file_delete(writer, 0, 341, 44699));

}

typedef struct {
    char *name;
    int id;
} CfToDrop;

std::vector<CfToDrop*> read_cf_drop_names() {
    std::vector<CfToDrop*> names;
    // the entries in the file are prefixed with this
//    int prefix_len = strlen("  \"ColumnFamilyAdd\": \"");
//    FILE *cfs_to_drop = fopen("amgen_CFs_sorted.txt", "r");
    FILE *cfs_to_drop = fopen("amgen_CFs_to_drop_with_ids.csv", "r");
    char buf[200000];
    int bytes_read = fread(buf, 1, 200000, cfs_to_drop);
//    printf("Read %d bytes\n", bytes_read);
    char *record = buf;
    do {
        if (*record == '\n') {
            record++;
        }
        if (*record != '#' && *record != 0) {
            CfToDrop *to_drop = (CfToDrop *) malloc(sizeof(CfToDrop));

//            record += prefix_len;
            int len = strchr(record, ',') - record;
            to_drop->name = (char *) malloc(len + 1);
            memcpy(to_drop->name, record, len);
            to_drop->name[len] = 0;

            record += len + 1;
            to_drop->id = atoi(record);

            if (to_drop->id > 0/* && to_drop->id < 5391*/) {
                names.push_back(to_drop);
            } else {
                fprintf(stderr, "Ignored CF %s\n", to_drop->name);
            }
        }
    } while ((record = strchr(record, '\n')) != NULL);
    return names;
}

void generate_cf_drop_log_records(std::vector<CfToDrop*> cfs_to_drop) {
    EnvOptions options;
    Env *env = Env::Default();
    std::unique_ptr<WritableFile> wfile;
    std::string filename("amgen_drop_records");
    OK(env->NewWritableFile(filename, &wfile, options));

    std::unique_ptr<WritableFileWriter> file_writer(new WritableFileWriter(
            std::move(wfile),
            (std::string &) filename,
            options));

    log::Writer writer(std::move(file_writer), 999999999, false);

    // added after i realized we cant write a separate file due to the 32k block structure
    // which necessitates padding
    {
        std::unique_ptr<SequentialFile> rfile;
        const char *manifest_file_name = "/home/jbalint/dl/amgen_manifest/MANIFEST-175839.orig";
        OK(env->NewSequentialFile(manifest_file_name, &rfile, options));

        std::unique_ptr<SequentialFileReader> file_reader(new SequentialFileReader(std::move(rfile),
                                                                                   manifest_file_name));

        int log_number = 1234; // TODO: need to compute this from the file name? or accept in argv
        log::Reader log_reader(logger,
                               std::move(file_reader), nullptr, true, log_number, false);

        Slice record;
        std::string scratch;
        while (log_reader.ReadRecord(&record, &scratch)) {
            VersionEdit edit;
            OK(edit.DecodeFrom(record));

            std::string buf;
            edit.EncodeTo(&buf);

            OK(writer.AddRecord(buf));
        }
    }

    for (auto cf = cfs_to_drop.begin(); cf != cfs_to_drop.end(); ++cf) {
        std::string buf;
        VersionEdit record;
        record.DropColumnFamily();
        record.SetColumnFamily((*cf)->id);
        record.EncodeTo(&buf);

        if (DEBUG) {
            printf("Record contents to drop %s/%d: ", (*cf)->name, (*cf)->id);
            for (int i = 0; i < buf.length(); ++i) {
                printf("%02x ", (unsigned char) buf[i]);
            }
            printf("\n");
        }

        OK(writer.AddRecord(buf));
    }

}

int main(int argc, const char *argv[]) {
    argc--;
    if (argc == 2 && !strcmp(argv[1], "-dump")) {
        dump_log(argv[2]);
    } else {
//        do_append();
        std::vector<CfToDrop*> names = read_cf_drop_names();
        generate_cf_drop_log_records(names);
    }
}
