#include <bitcask/bitcask.h>
#include <bitcask/errors.h>
#include <bitcask/format.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <iostream>
#include <set>
#include <thread>

#include "catch.hpp"
#include "temp_directory.h"

#if defined(__linux__)
#include <sys/resource.h>
#endif

namespace {

constexpr bitcask::Options kDefaultOptions{
    .max_file_size = 32ull << 20,
    .compaction_levels = 1,
};

} // namespace

TEST_CASE("Create database") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  REQUIRE_FALSE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));
}

TEST_CASE("Enumerate keys") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  REQUIRE_FALSE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));
  for (size_t i = 0; i < 5; ++i) {
    db->Put({}, std::to_string(i), std::to_string(i));
  }

  db->Delete({}, "2");
  std::set<std::string> keys;
  db->Enumerate([&](const std::string_view key) { keys.emplace(key); });
  REQUIRE(keys.size() == 4);
  CHECK(keys.contains("0"));
  CHECK(keys.contains("1"));
  CHECK(keys.contains("3"));
  CHECK(keys.contains("4"));
}

TEST_CASE("Check consistency on read") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  REQUIRE_FALSE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));
  REQUIRE_FALSE(db->Put({}, "abc", "test"));
  db.reset();

  const auto path = temp_dir.GetPath() + "/0-2.dat";
  REQUIRE(std::filesystem::exists(path));
  int fd = ::open(path.c_str(), O_WRONLY);
  REQUIRE(fd != -1);
  REQUIRE(
      ::pwrite(fd, "x", 1,
          sizeof(bitcask::format::Header) + sizeof(uint64_t) + sizeof(bitcask::format::Entry) + 2) != -1);
  ::close(fd);

  REQUIRE_FALSE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));
  std::string value;
  REQUIRE_FALSE(db->Get({.verify_checksums = false}, "abc", &value));
  CHECK(value == "text");

  REQUIRE(db->Get({.verify_checksums = true}, "abc", &value));
}

TEST_CASE("Key overflow") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  REQUIRE_FALSE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));

  std::string key;
  key.resize(std::numeric_limits<uint16_t>::max() + 100);
  key[1050] = 'a';

  REQUIRE(db->Put({}, key, "test"));
  db.reset();

  REQUIRE_FALSE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));
  CHECK(db->Get({}, key, nullptr));
}

TEST_CASE("Load sections") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  REQUIRE_FALSE(
      bitcask::Database::Open({.max_file_size = 16 << 10, .write_index = true}, temp_dir.GetPath(), db));

  const std::string value = "some content larger than header";
  REQUIRE_FALSE(db->Put({}, "1", value));
  REQUIRE_FALSE(db->Put({}, "2", value));
  REQUIRE_FALSE(db->Put({}, "3", value));
  REQUIRE_FALSE(db->Rotate());
  REQUIRE_FALSE(db->Put({}, "4", value));
  REQUIRE_FALSE(db->Put({}, "5", value));
  REQUIRE_FALSE(db->Rotate());
  REQUIRE_FALSE(db->Pack(true));
  REQUIRE_FALSE(db->Put({}, "6", value));
  REQUIRE_FALSE(db->Put({}, "7", value));
  REQUIRE_FALSE(db->Rotate());
  REQUIRE_FALSE(db->Pack(true));
}

TEST_CASE("Non existent") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  REQUIRE_FALSE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));
  std::string value;
  REQUIRE(db->Get({}, "abc", &value));
  REQUIRE(db->Get({}, "abc", nullptr));
  REQUIRE_FALSE(db->Delete({}, "abc"));
}

TEST_CASE("Read after reopen") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;
  auto options = kDefaultOptions;
  options.flush_mode = bitcask::FlushMode::kImmediately;

  REQUIRE_FALSE(bitcask::Database::Open(options, temp_dir.GetPath(), db));
  REQUIRE_FALSE(db->Put({}, "abc", "test"));
  REQUIRE_FALSE(db->Put({}, "abc", "text"));

  db.reset();

  REQUIRE_FALSE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));

  std::string value;
  REQUIRE_FALSE(db->Get({}, "abc", &value));
  CHECK(value == "text");
}

TEST_CASE("Read range") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;
  std::string value;

  REQUIRE_FALSE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));

  REQUIRE_FALSE(db->Put({}, "abc", "test"));

  // Without crc check.
  REQUIRE_FALSE(db->Get({.range = bitcask::Range{1, 2}}, "abc", &value));
  CHECK(value == "es");
  // Without crc check (empty result).
  REQUIRE_FALSE(db->Get({.range = bitcask::Range{4, 0}}, "abc", &value));
  CHECK(value == "");
  // With crc check.
  REQUIRE_FALSE(db->Get({.verify_checksums = true, .range = bitcask::Range{1, 3}}, "abc", &value));
  CHECK(value == "est");

  // Invalid range (offset).
  REQUIRE(db->Get({.range = bitcask::Range{5, 0}}, "abc", &value));
  // Invalid range (size).
  REQUIRE(db->Get({.range = bitcask::Range{0, 5}}, "abc", &value));
  REQUIRE(db->Get({.range = bitcask::Range{1, 4}}, "abc", &value));
}

TEST_CASE("Record large than max size of file") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  bitcask::Options options{.max_file_size = 64ull << 10};

  std::string data;
  data.resize(128ull << 10);
  for (size_t i = 0; i < data.size(); ++i) {
    data[i] = i % 256;
  }
  data[123456] = 'a';

  REQUIRE_FALSE(bitcask::Database::Open(options, temp_dir.GetPath(), db));
  REQUIRE_FALSE(db->Put({}, "abc", data));
  REQUIRE_FALSE(db->Pack(true));

  db.reset();

  REQUIRE_FALSE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));
  std::string value;
  REQUIRE_FALSE(db->Get({}, "abc", &value));
  CHECK(data == value);
}

TEST_CASE("Unknown file in the directory") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  REQUIRE_FALSE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));
  REQUIRE_FALSE(db->Put({}, "abc", "test"));
  db.reset();

  const auto path = temp_dir.GetPath() + "/5-100.dat";
  const auto data = std::string_view("some content larger than header");
  int fd = ::open(path.c_str(), O_WRONLY | O_CREAT, 0666);
  REQUIRE(fd != -1);
  REQUIRE(::write(fd, data.data(), data.size()) != -1);
  ::close(fd);

  REQUIRE_FALSE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));
  std::string value;
  REQUIRE_FALSE(db->Get({.verify_checksums = true}, "abc", &value));
  CHECK(value == "test");
}

TEST_CASE("Update value") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  REQUIRE_FALSE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));

  REQUIRE_FALSE(db->Put({}, "abc", "test"));
  REQUIRE_FALSE(db->Put({}, "abc", "text"));
  std::string value;
  REQUIRE_FALSE(db->Get({}, "abc", &value));
  CHECK(value == "text");
}

TEST_CASE("Write / Read / Delete") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  REQUIRE_FALSE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));

  REQUIRE_FALSE(db->Put({}, "abc", "test"));
  std::string value;
  REQUIRE_FALSE(db->Get({}, "abc", &value));
  CHECK(value == "test");
  REQUIRE_FALSE(db->Delete({}, "abc"));
  REQUIRE(db->Get({}, "abc", nullptr));
}

TEST_CASE("Delete no flush") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  auto options = kDefaultOptions;
  options.flush_mode = bitcask::FlushMode::kImmediately;
  options.flush_mode_for_delete = bitcask::FlushMode::kOnClose;

  REQUIRE_FALSE(bitcask::Database::Open(options, temp_dir.GetPath(), db));

  REQUIRE_FALSE(db->Put({}, "abc", "test"));
  std::string value;
  REQUIRE_FALSE(db->Get({}, "abc", &value));
  CHECK(value == "test");
  REQUIRE_FALSE(db->Delete({}, "abc"));
  REQUIRE(db->Get({}, "abc", nullptr));
}

TEST_CASE("Write multiple active files") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  REQUIRE_FALSE(
      bitcask::Database::Open({.active_files = 3, .max_file_size = 16 << 10}, temp_dir.GetPath(), db));
  const std::string value = "some content larger than header";
  for (size_t i = 0; i < 1000; ++i) {
    db->Put({}, std::to_string(i), value + std::to_string(i));
  }

  std::string tmp;
  REQUIRE_FALSE(db->Get({.verify_checksums = true}, std::to_string(512), &tmp));
  CHECK(tmp == "some content larger than header512");
}

TEST_CASE("Flush with delay") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  REQUIRE_FALSE(bitcask::Database::Open(
      {.flush_mode = bitcask::FlushMode::kDelay, .max_file_size = 16 << 10}, temp_dir.GetPath(), db));

  std::vector<std::thread> threads;
  const std::string value = "some content larger than header";
  const auto do_write = [&] {
    for (size_t i = rand() % 10; i < 50; ++i) db->Put({}, std::to_string(i), value);
  };

  threads.emplace_back(do_write);
  threads.emplace_back(do_write);
  threads.emplace_back(do_write);
  threads.emplace_back(do_write);
  threads.emplace_back(do_write);

  for (auto& t : threads) {
    if (t.joinable()) {
      t.join();
    }
  }
  std::string tmp;
  auto s = db->Get({}, "12", &tmp);
  CHECK(tmp == value);
}

TEST_CASE("Write single key by multiple threads") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  REQUIRE_FALSE(bitcask::Database::Open({.max_file_size = 16 << 10}, temp_dir.GetPath(), db));

  std::vector<std::thread> threads;
  const std::string value = "some content larger than header";
  const auto do_check = [&] {
    for (size_t i = 0; i < 5000; ++i) db->Get({}, "abc", nullptr);
  };
  const auto do_delete = [&] {
    for (size_t i = 0; i < 50; ++i) db->Delete({}, value);
  };
  const auto do_write = [&] {
    for (size_t i = 0; i < 1000; ++i) db->Put({}, "abc", value);
  };

  threads.emplace_back(do_write);
  threads.emplace_back(do_check);
  threads.emplace_back(do_write);
  threads.emplace_back(do_write);
  threads.emplace_back(do_delete);
  threads.emplace_back(do_write);
  threads.emplace_back(do_write);
  threads.emplace_back(do_write);
  threads.emplace_back(do_delete);
  threads.emplace_back(do_write);
  threads.emplace_back(do_delete);
  threads.emplace_back(do_check);
  threads.emplace_back(do_delete);
  threads.emplace_back(do_write);
  threads.emplace_back(do_write);
  threads.emplace_back(do_delete);
  threads.emplace_back(do_write);

  for (auto& t : threads) {
    if (t.joinable()) {
      t.join();
    }
  }
  std::string tmp;
  auto s = db->Get({}, "abc", &tmp);
  CHECK((bitcask::IsNotFound(s) || (!s && tmp == value)));
}

#ifdef __linux__
TEST_CASE("Limit of opened files") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  REQUIRE_FALSE(bitcask::Database::Open({.max_file_size = 4 << 10}, temp_dir.GetPath(), db));

  std::string s;
  s.resize(1024);
  for (size_t i = 0; i < s.size(); ++i) {
    s[i] = i % 256;
  }
  for (size_t i = 0; i < 4 * 16; ++i) {
    db->Put({}, std::to_string(i), s);
  }

  db->Rotate();

  rlimit limits{.rlim_cur = 16, .rlim_max = 16};
  CHECK(::setrlimit(RLIMIT_NOFILE, &limits) != -1);

  for (size_t i = 0; i < 4 * 16;) {
    std::string tmp;
    auto ec = db->Get({}, std::to_string(i), &tmp);
    if (ec == std::errc::too_many_files_open) {
      db->CloseFiles();
    } else {
      INFO(ec.message());
      REQUIRE_FALSE(ec);
      CHECK(tmp == s);
      ++i;
    }
  }
}

#endif
