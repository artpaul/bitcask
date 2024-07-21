#include <bitcask/bitcask.h>

#include <iostream>

#include "catch.hpp"
#include "temp_directory.h"

namespace {

constexpr bitcask::Options kDefaultOptions{
    .max_file_size = 32ull << 20,
};

} // namespace

TEST_CASE("Create database") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  REQUIRE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));
}

TEST_CASE("Write / Read / Delete") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  REQUIRE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));

  REQUIRE(db->Put({}, "abc", "test"));
  std::string value;
  REQUIRE(db->Get({}, "abc", &value));
  CHECK(value == "test");
  REQUIRE(db->Delete({}, "abc"));
  REQUIRE_FALSE(db->Get({}, "abc", nullptr));
}

TEST_CASE("Update value") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  REQUIRE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));

  REQUIRE(db->Put({}, "abc", "test"));
  REQUIRE(db->Put({}, "abc", "text"));
  std::string value;
  REQUIRE(db->Get({}, "abc", &value));
  CHECK(value == "text");
}

TEST_CASE("Non existent") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  REQUIRE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));
  std::string value;
  REQUIRE_FALSE(db->Get({}, "abc", &value));
  REQUIRE_FALSE(db->Get({}, "abc", nullptr));
  REQUIRE(db->Delete({}, "abc"));
}

TEST_CASE("Read after reopen") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;
  auto options = kDefaultOptions;
  options.data_sync = true;

  REQUIRE(bitcask::Database::Open(options, temp_dir.GetPath(), db));
  REQUIRE(db->Put({}, "abc", "test"));
  REQUIRE(db->Put({}, "abc", "text"));

  db.reset();

  REQUIRE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));

  std::string value;
  REQUIRE(db->Get({}, "abc", &value));
  CHECK(value == "text");
}

TEST_CASE("Check consistency on read") {
  TemporaryDirectory temp_dir;
  std::unique_ptr<bitcask::Database> db;

  REQUIRE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));
  REQUIRE(db->Put({}, "abc", "test"));
  db.reset();

  const auto path = temp_dir.GetPath() + "/00-0000-2.dat";
  REQUIRE(std::filesystem::exists(path));
  int fd = ::open(path.c_str(), O_WRONLY);
  REQUIRE(fd != -1);
  REQUIRE(::pwrite(fd, "x", 1, sizeof(uint64_t) + sizeof(bitcask::detail::Entry) + 2) != -1);
  ::close(fd);

  REQUIRE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));
  std::string value;
  REQUIRE(db->Get({.verify_checksums = false}, "abc", &value));
  CHECK(value == "text");

  REQUIRE_FALSE(db->Get({.verify_checksums = true}, "abc", &value));
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

  REQUIRE(bitcask::Database::Open(options, temp_dir.GetPath(), db));
  REQUIRE(db->Put({}, "abc", data));
  REQUIRE(db->Pack(true));

  db.reset();

  REQUIRE(bitcask::Database::Open(kDefaultOptions, temp_dir.GetPath(), db));
  std::string value;
  REQUIRE(db->Get({}, "abc", &value));
  CHECK(data == value);
}
