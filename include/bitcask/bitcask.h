#pragma once

#include <string.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <numeric>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#define XXH_INLINE_ALL
#include "xxhash.h"

#if defined(__linux__) || defined(__APPLE__)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#else
#error "Platform is not supported"
#endif

namespace bitcask {
namespace detail {

static constexpr size_t kFileMagicSize = 6;

static constexpr uint16_t kFileFlagNone = 0x00;
static constexpr uint16_t kFileFlagWithIndex = 0x01;

static constexpr uint16_t kEntryFlagTombstone = 0x01;

// |------------------------------------------------------------|
// |                The layout of the data record               |
// |------------------------------------------------------|-----|
// | 64 bit | 64 bit | 16 bit |16 bit  | 32 bit   | var   | var |
// |--------|--------|--------|--------|----------|-------|-----|
// | crc    | tstamp | flags  | key_sz | value_sz | value | key |
// |------------------------------------------------------|-----|
//                                                ^
//                                       In-memory pointer.

struct Header {
  /// Magic constant ('BCSK') to identify the type of the file.
  char magic[kFileMagicSize];
  /// Various flags for the data file.
  uint16_t flags;
};

struct Entry {
  /// The update time of the record.
  uint64_t timestamp;
  /// Various flags for the entry.
  uint16_t flags;
  /// The size of the record's key.
  uint16_t key_size;
  /// The size of the record's value.
  uint32_t value_size;

  constexpr bool is_tobstone() const noexcept { return (flags & kEntryFlagTombstone) != 0; }
};

struct Index {
  /// The update time of the record.
  uint64_t timestamp;
  /// Various flags for the entry.
  uint16_t flags;
  /// The size of the record's key.
  uint16_t key_size;
  /// The size of the record's value.
  uint32_t value_size;
  /// The offset to the record's value from the begginning of the section with
  /// entries.
  uint64_t value_pos;
};

struct Footer {
  /// Offset from the begginning of the file to the beginning of section with
  /// entries.
  uint64_t entries;
  /// Offset from the begginning of the file to the beginning of section with
  /// index.
  uint64_t index;
};

static_assert(sizeof(Header) == 8);
static_assert(sizeof(Entry) == 16);
static_assert(sizeof(Index) == 24);
static_assert(sizeof(Footer) == 16);

} // namespace detail

class Status {
  enum class Code {
    kSuccess = 0,
    /// Requested entity was not found.
    kNotFound,
    /// Requested operation already in progress.
    kInProgress,
    /// IO error.
    kIOError,
    /// Inconsistent state of the database.
    kInconsistent,
    /// Database was opened in read-only mode.
    kReadOnly,
  };

 public:
  constexpr Status() noexcept = default;

  static constexpr Status Success() noexcept { return Status(); }

  static constexpr Status Inconsistent() noexcept { return Status(Code::kInconsistent); }

  static constexpr Status InProgress() noexcept { return Status(Code::kInProgress); }

  static constexpr Status NotFound() noexcept { return Status(Code::kNotFound); }

  static constexpr Status IOError(int errnum) noexcept { return Status(Code::kIOError, errnum); }

  static constexpr Status ReadOnly() noexcept { return Status(Code::kReadOnly); }

  std::string Message() const {
    switch (code_) {
      case Code::kSuccess:
        return "OK";
      case Code::kNotFound:
        return "Not found";
      case Code::kInconsistent:
        return "Inconsistent";
      case Code::kInProgress:
        return "In progress";
      case Code::kIOError:
        return ::strerror(errno_);
      case Code::kReadOnly:
        return "Readn only";
    }
    return {};
  }

 public:
  /// Returns true if the status indicates InProgress error.
  constexpr bool IsInProgress() const noexcept { return code_ == Code::kInProgress; }

  /// Returns true if the status indicates a NotFound error.
  constexpr bool IsNotFound() const noexcept { return code_ == Code::kNotFound; }

  /// Returns true if the status indicates success.
  constexpr bool IsSuccess() const noexcept { return code_ == Code::kSuccess; }

  /// Returns true if the status indicates IO error.
  constexpr bool IsIOError() const noexcept { return code_ == Code::kIOError; }

  /// Returns true if the status indicates read-only mode.
  constexpr bool IsReadOnly() const noexcept { return code_ == Code::kReadOnly; }

  explicit constexpr operator bool() const noexcept { return IsSuccess(); }

 private:
  constexpr Status(Code code, int errnum = 0) noexcept : code_(code), errno_(errnum) {}

 private:
  Code code_{Code::kSuccess};
  /// System error number.
  int errno_;
};

struct Options {
  uint32_t max_file_size = std::numeric_limits<uint32_t>::max();

  /// Flush in-core data to storage device after write.
  bool data_sync = false;

  /// If true, the store will be opened in read-only mode.
  bool read_only = false;

  /// Write index at the end of each merged file.
  bool write_index = false;
};

/**
 * Options that control read operations.
 */
struct ReadOptions {
  /// If true, all data read from underlying storage will be
  /// verified against corresponding checksums.
  bool verify_checksums = false;

  /// If the size of the read value is greater than the specified size, the
  /// operation will fail.
  uint32_t max_value_size = std::numeric_limits<uint32_t>::max();
};

/**
 * Options that control write operations.
 */
struct WriteOptions {
  /// If true, the write will be flushed from the operating system buffer cache
  /// before the write is considered complete.  If this flag is true, writes
  /// will be slower.
  bool sync = false;
};

class Database {
  enum class CompactionMode {
    /// Push data to the next compaction level.
    kScatter = 1,
    /// Gather multiple data files into single one.
    kGather = 2,
  };

  struct FileInfo {
    /// Path to the data file.
    std::filesystem::path path;

    /// The mutex should be hold during the read to avoid closing the file
    /// descriptor on rotation of active file.
    std::shared_mutex read_mutex;

    // The mutex should be used to prevent multiple threads open the same file
    // for reading simultaneously.
    std::mutex fd_mutex;
    /// File descriptor.
    int fd{-1};

    /// Size of the data written so far.
    /// The size is only updated on writing.
    std::atomic_uint64_t size{0};

   public:
    FileInfo(std::filesystem::path p, uint64_t s) noexcept : path(std::move(p)), size(s) {}

#ifndef NDEBUG
    ~FileInfo() {
      // Check there are no leaks of file descriptors.
      assert(fd == -1);
    }
#endif

    /// Waits for the completion of all ongoing reads and closes the file
    /// descriptor.
    void CloseFile(bool data_sync = false) {
      int prev_fd = -1;

      {
        // Wait until all possible readings from the file have been completed.
        std::lock_guard read_lock(read_mutex);
        // Acquire exclusive access to file descriptor.
        std::lock_guard fd_lock(fd_mutex);

        assert(fd != -1);
        // After resetting the file descriptor, a concurrent thread can open the
        // file for reading.
        std::swap(fd, prev_fd);
      }

      // Flush data if needed.
      if (data_sync) {
        ::fsync(prev_fd);
      }
      // Close the file descriptor.
      ::close(prev_fd);
    }

    /// Checks file is opened otherwise opens it in read-only mode.
    Status EnsureReadable() {
      // Acquire exclusive access to a file descriptor to avoid opening the file
      // multiple times.
      std::lock_guard fd_lock(fd_mutex);

      if (fd == -1) {
        fd = ::open(path.c_str(), O_RDONLY);
        // Cannot open file for reading.
        if (fd == -1) {
          return Status::IOError(errno);
        }
      }

      return {};
    }
  };

  struct Record {
    /// Data file contained the record.
    FileInfo* file;
    /// Time the record was written.
    uint64_t timestamp;
    /// Offset to the beginning of the record's value within the data file.
    uint32_t offset;
    /// Size of the value.
    uint32_t size;
  };

  static_assert(std::is_trivial_v<Record>);
  static_assert(sizeof(Record) == sizeof(void*) + 16);

  using FileInfoStatus = std::pair<std::shared_ptr<FileInfo>, Status>;

 public:
  ~Database() {
    if (active_file_) {
      active_file_->CloseFile(options_.data_sync);
    }
    for (const auto& parts : files_) {
      std::for_each(parts.begin(), parts.end(), [this](const auto& f) {
        if (f->fd != -1) {
          f->CloseFile(options_.data_sync);
        }
      });
    }
  }

  static Status Open(
      const Options& options, const std::filesystem::path& path, std::unique_ptr<Database>& db) {
    db = std::unique_ptr<Database>(new Database(options, path));
    // Scan database directory.
    if (auto status = db->Initialize(); !status) {
      return status;
    }
    return {};
  }

 public:
  Status Delete(const WriteOptions& options, const std::string_view key) {
    std::shared_lock op_lock(operation_mutex_);

    if (options_.read_only) {
      return Status::ReadOnly();
    }

    const auto timestamp = [this](const auto key) -> std::optional<uint64_t> {
      std::shared_lock key_lock(key_mutex_, std::defer_lock);

      LockKey(key, &key_lock);

      if (GetKeyNoLock(key)) {
        return ++clock_;
      } else {
        UnlockKey(key);
        return {};
      }
    }(key);

    if (!timestamp) {
      return {};
    }

    [[maybe_unused]] Defer d([this, key] { UnlockKey(key); });
    // Write the tombstone.
    auto [_, status] = WriteEntry(key, {}, timestamp.value(), true, options.sync);
    if (!status) {
      return status;
    }

    // Update key-set
    if (updated_keys_) {
      std::unique_lock key_lock(key_mutex_);

      const bool present_in_main = keys_.contains(key);
      // During the merging process only the updated_keys_ can be modified.
      if (auto ki = updated_keys_->find(key); ki != updated_keys_->end()) {
        if (present_in_main) {
          ki->second = Record{};
        } else {
          updated_keys_->erase(ki);
        }
      } else if (present_in_main) {
        updated_keys_->emplace(std::string(key), Record{});
      }
    } else {
      std::unique_lock key_lock(key_mutex_);

      if (auto ki = keys_.find(key); ki != keys_.end()) {
        keys_.erase(ki);
      }
    }

    return {};
  }

  Status Get(const ReadOptions& options, const std::string_view key, std::string* value) const {
    std::shared_lock op_lock(operation_mutex_);

    // Looking up for the actual state of the key.
    const auto record = [this](const auto key) -> std::optional<Record> {
      std::shared_lock key_lock(key_mutex_, std::defer_lock);

      WaitKeyUnlocked(key, key_lock);

      return GetKeyNoLock(key);
    }(key);

    if (record) {
      return ReadValue(options, *record, *value);
    }

    return Status::NotFound();
  }

  /// Put an object into the database.
  Status Put(const WriteOptions& options, const std::string_view key, const std::string_view value) {
    std::shared_lock op_lock(operation_mutex_);

    if (options_.read_only) {
      return Status::ReadOnly();
    }
    // Acquire exclusive access to the key.
    LockKey(key, nullptr);

    const uint64_t timestamp = ++clock_;

    [[maybe_unused]] Defer d([this, key] { UnlockKey(key); });
    // Write the value with the specific timestamp.
    auto [record, status] = WriteEntry(key, value, timestamp, false, options.sync);
    if (!status) {
      return status;
    }

    // Update key-set
    if (updated_keys_) {
      std::unique_lock key_lock(key_mutex_);

      // During the merging process only the updated_keys_ can be modified.
      updated_keys_->insert_or_assign(std::string(key), record);
    } else {
      std::unique_lock key_lock(key_mutex_);

      keys_.insert_or_assign(std::string(key), record);
    }

    return {};
  }

 public:
  Status Pack(bool force = false) {
    for (int cell = 0; true; cell++) {
      std::vector<std::shared_ptr<FileInfo>> files;
      CompactionMode mode = CompactionMode::kScatter;

      {
        std::unique_lock op_lock(operation_mutex_);

        // Check whether the compaction process is already in progress.
        if (updated_keys_) {
          return Status::InProgress();
        }

        std::lock_guard file_lock(file_mutex_);
        // Stop if all portions were processed.
        if (cell >= files_.size()) {
          return {};
        } else if (cell > 0) {
          if (!force && files_[cell].size() < 4) {
            continue;
          }
        }
        // Grab all accumulated L0 files for processing.
        files.swap(files_[cell]);
        // Check if there is something to process.
        if (files.empty()) {
          continue;
        }
        // Choose compation mode.
        mode = (cell == 0) ? CompactionMode::kScatter : CompactionMode::kGather;

        // Create a key-set for buffering updates during the merge.
        updated_keys_ = std::make_unique<unordered_string_map<Record>>();
      }

      auto status = PackFiles(std::move(files), mode, cell);

      {
        std::unique_lock op_lock(operation_mutex_);

        // Merge updated keys with the main key-set.
        for (const auto& [key, record] : *updated_keys_) {
          if (const auto ki = keys_.find(key); ki == keys_.end()) {
            assert(record.timestamp != 0);

            keys_.emplace(key, record);
          } else if (record.timestamp == 0) {
            keys_.erase(ki);
          } else {
            ki->second = record;
          }
        }

        updated_keys_.reset();
      }

      if (!status) {
        return status;
      }
    }

    return {};
  }

  /// Closes current active file.
  Status Rotate() {
    std::shared_lock op_lock(operation_mutex_);
    std::shared_ptr<FileInfo> file;

    if (options_.read_only) {
      return Status::ReadOnly();
    }

    {
      // Acquire exclusive access for writing to active file.
      std::lock_guard write_lock(write_mutex_);
      // Check if there is a file opened for writing.
      if (active_file_) {
        file.swap(active_file_);
      } else {
        return {};
      }
    }

    // Close the active file.
    file->CloseFile(options_.data_sync);

    // Acquire exclusive access to the list of data files.
    std::lock_guard file_lock(file_mutex_);
    // Move data file into the read-only set.
    files_[0].push_back(std::move(file));

    return {};
  }

 private:
  class Defer {
   public:
    Defer() noexcept = default;

    explicit Defer(std::function<void()> cb) noexcept : cb_(std::move(cb)) {}

    ~Defer() {
      if (cb_) {
        cb_();
      }
    }

   private:
    std::function<void()> cb_;
  };

  Database(const Options& options, const std::filesystem::path& path)
      : options_(options), base_path_(path) {
    // Allocate two LSMT levels.
    files_.resize(1 + 8);
  }

  Status Initialize() {
    std::unordered_map<std::string, uint64_t> tombstones;

    const auto cb = [&](const Record& record, const bool is_tombstone, std::string key,
                        std::string value) -> Status {
      clock_ = std::max<uint64_t>(clock_, record.timestamp);

      const auto ti = tombstones.find(key);
      // Process tombstone.
      if (is_tombstone) {
        if (ti == tombstones.end()) {
          tombstones.emplace(key, record.timestamp);
        } else if (ti->second < record.timestamp) {
          ti->second = record.timestamp;
        }

        if (auto ki = keys_.find(key); ki != keys_.end()) {
          if (ki->second.timestamp < record.timestamp) {
            keys_.erase(ki);
          }
        }

        return {};
      }

      // The record will be deleted in the future. Skip it.
      if (ti != tombstones.end() && record.timestamp < ti->second) {
        return {};
      }

      if (const auto ki = keys_.find(key); ki == keys_.end()) {
        keys_.emplace(key, record);
      } else if (ki->second.timestamp < record.timestamp) {
        ki->second = record;
      }

      return {};
    };

    for (const auto& entry : std::filesystem::directory_iterator(base_path_)) {
      if (!entry.is_regular_file()) {
        continue;
      }

      auto index = ParseLayoutIndex(entry.path().filename().string());
      if (!index || index.value() > 10000) {
        continue;
      }

      auto file = std::make_shared<FileInfo>(entry.path(), entry.file_size());
      // Open file for reading.
      if (auto s = file->EnsureReadable(); !s) {
        return s;
      }
      [[maybe_unused]] Defer do_close([file]() { file->CloseFile(); });
      // Read entries from the file.
      if (auto s = EnumerateEntriesNoLock(file, cb); !s) {
        if (s.IsNotFound()) {
          continue;
        }
        return s;
      }

      // Move data file into the read-only set.
      files_.resize(std::max<size_t>(files_.size(), index.value() + 1));
      files_[index.value()].push_back(std::move(file));
    }
    return {};
  }

  Status PackFiles(
      const std::vector<std::shared_ptr<FileInfo>>& files, const CompactionMode mode, const int cell) {
    std::vector<std::vector<std::shared_ptr<FileInfo>>> output(8);
    std::vector<std::pair<decltype(keys_)::iterator, Record>> updates;

    static_assert(std::is_trivially_destructible_v<decltype(updates)::value_type>);

    const auto cb = [&](const Record& record, const bool is_tombstone, std::string key,
                        std::string value) -> Status {
      auto ki = keys_.find(key);
      if (ki == keys_.end()) {
        if (mode == CompactionMode::kGather && cell > 0) {
          return {};
        }
      } else if (ki->second.timestamp != record.timestamp) {
        assert(ki->second.timestamp > record.timestamp);
        return {};
      }

      const auto [rec, status] = WriteEntryToFile(key, value, record.timestamp, is_tombstone, false,
          // Target file provider.
          [&](const size_t length) -> FileInfoStatus {
            const auto& [i, index] = [&]() -> std::tuple<int, int> {
              if (mode == CompactionMode::kGather) {
                return {0, cell};
              } else {
                size_t i = XXH32(key.data(), key.size(), 1) % 8;

                return {i, cell * 8 + i + 1};
              }
            }();

            if (output[i].empty() || output[i].back()->size + length > options_.max_file_size) {
              auto [file, status] =
                  MakeWritableFile(std::to_string(index) + "-" + std::to_string(++clock_) + ".dat", false);
              if (!status) {
                return {{}, status};
              }

              output[i].push_back(std::move(file));
            }
            return {output[i].back(), {}};
          });

      if (status) {
        updates.emplace_back(ki, rec);
      } else {
        return status;
      }

      return {};
    };

    for (const auto& file : files) {
      // Acquiring read lock to prevent closing the file handle during the
      // read.
      std::shared_lock read_lock(file->read_mutex);

      // Ensure source file is opened.
      file->EnsureReadable();
      // Enumerate all records in the source file.
      if (auto s = EnumerateEntriesNoLock(file, cb); !s) {
        read_lock.unlock();
        // TODO: finalize.
        return s;
      }

      {
        std::lock_guard key_lock(key_mutex_);
        // Assign new location for the entries read from the current file.
        for (const auto& [ki, record] : updates) {
          ki->second = record;
        }
      }

      updates.clear();
    }

    // Close output files.
    // Ensure all data was written to the storage device
    // before the source files will be deleted.
    for (const auto& f : output) {
      std::for_each(f.begin(), f.end(), [](auto& f) { f->CloseFile(true); });
    }
    // Cleanup processed files.
    for (const auto& file : files) {
      assert(file.use_count() == 1);

      file->CloseFile();
      // Remove processed file from the storage device.
      std::filesystem::remove(file->path);
    }

    {
      std::lock_guard file_lock(file_mutex_);

      for (size_t i = 0, end = output.size(); i != end; ++i) {
        files_[1 + i].insert(files_[1 + i].end(), output[i].begin(), output[i].end());
      }
    }

    return {};
  }

 private:
  std::optional<Record> GetKeyNoLock(const std::string_view key) const {
    // Check if the key was updated during merging process.
    if (updated_keys_) {
      if (auto ki = updated_keys_->find(key); ki != updated_keys_->end()) {
        if (ki->second.timestamp) {
          return ki->second;
        } else {
          return {};
        }
      }
    }
    // Search in the main key-set.
    if (const auto ki = keys_.find(key); ki != keys_.end()) {
      return ki->second;
    }
    return {};
  }

  /// Sets lock to individual key.
  void LockKey(const std::string_view key, std::shared_lock<std::shared_mutex>* lock) {
    std::unique_lock lock_lock(lock_mutex_);

    // Wait the key will be unlocked by a concurent thread.
    while (key_locks_.contains(key)) {
      lock_cond_.wait(lock_lock);
    }
    // Set lock to the key.
    key_locks_.insert(key);

    if (lock) {
      lock->lock(); // Is deadlock possible?
    }
  }

  /// Unlock an individual key.
  void UnlockKey(const std::string_view key) {
    std::unique_lock lock_lock(lock_mutex_);

    if (key_locks_.erase(key) == 0) {
      std::terminate();
    }

    lock_cond_.notify_all();
  }

  /// Waits individual key will be unlocked.
  template <typename K>
  void WaitKeyUnlocked(const std::string_view key, K& lock) const {
    std::unique_lock lock_lock(lock_mutex_);

    // Wait the key will be unlocked by a concurent thread.
    while (key_locks_.contains(key)) {
      lock_cond_.wait(lock_lock);
    }

    lock.lock(); // Is deadlock possible?
  }

 private:
  Status EnumerateEntriesNoLock(const std::shared_ptr<FileInfo>& file,
      const std::function<Status(const Record&, const bool, std::string, std::string)>& cb) const {
    size_t offset = 0;
    uint64_t file_size = file->size;
    detail::Header header;

    if (auto s = LoadFromFile(file->fd, &header, sizeof(header), offset); !s) {
      return s;
    } else if (std::memcmp(header.magic, "BCSKV1", detail::kFileMagicSize) != 0) {
      return Status::NotFound();
    }

    if (header.flags & detail::kFileFlagWithIndex) {
      detail::Footer footer;
      size_t footer_offset = file->size - sizeof(footer);
      if (auto s = LoadFromFile(file->fd, &footer, sizeof(footer), footer_offset); !s) {
        return s;
      }
      file_size = footer.index;
    }

    while (offset < file_size) {
      detail::Entry e;
      std::string key;
      std::string value;
      auto [read, status] = ReadEntryImpl(file->fd, offset, false, e, key, value);
      if (!status) {
        return status;
      }

      const Record record{
          .file = file.get(),
          .timestamp = e.timestamp,
          .offset = uint32_t(offset + sizeof(uint64_t) + sizeof(detail::Entry)),
          .size = uint32_t(value.size()),
      };

      auto s = cb(record, (e.flags & detail::kEntryFlagTombstone), std::move(key), std::move(value));
      if (!s) {
        return s;
      }

      offset += read;
    }

    return {};
  }

  FileInfoStatus MakeWritableFile(const std::string& name, bool with_index) const {
    static constexpr std::filesystem::perms kDefaultPremissions =
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
        std::filesystem::perms::group_read | std::filesystem::perms::others_read;

    auto path = base_path_ / name;
    auto fd = ::open(path.c_str(), O_APPEND | O_RDWR | O_CREAT | O_EXCL, kDefaultPremissions);
    // Cannot open file for writing.
    if (fd == -1) {
      return {{}, Status::IOError(errno)};
    } else {
      const detail::Header header{.magic = {'B', 'C', 'S', 'K', 'V', '1'},
          .flags = with_index ? detail::kFileFlagWithIndex : detail::kFileFlagNone};

      if (::write(fd, &header, sizeof(header)) == -1) {
        int err = errno;
        ::close(fd);
        return {{}, Status::IOError(err)};
      }
    }
    auto file = std::make_shared<FileInfo>(std::move(path), sizeof(detail::Header));
    file->fd = fd;
    return {file, {}};
  }

  Status ReadValue(const ReadOptions& options, const Record& record, std::string& value) const {
    // Acquiring read lock to prevent closing the file handle during the read.
    std::shared_lock read_lock(record.file->read_mutex);

    // Ensure file is opened.
    record.file->EnsureReadable();

    if (options.verify_checksums) {
      size_t offset = record.offset - (sizeof(uint64_t) + sizeof(detail::Entry));
      detail::Entry e;
      std::string key;
      return std::get<1>(ReadEntryImpl(record.file->fd, offset, true, e, key, value));
    } else {
      size_t offset = record.offset;
      // Allocate memory for the value.
      value.resize(record.size);
      // Load value.
      return LoadFromFile(record.file->fd, value.data(), value.size(), offset);
    }
  }

  /// @brief Writes the data to the active data file.
  ///
  /// @returns written record or an error code if the write was unseccessful.
  std::pair<Record, Status> WriteEntry(const std::string_view key, const std::string_view value,
      const uint64_t timestamp, const bool is_tombstone, const bool sync) {
    std::unique_lock write_lock(write_mutex_, std::defer_lock);

    // Target file provider.
    const auto& file_provider = [&](const uint32_t length) -> FileInfoStatus {
      // Acquire exclusive access for writing to active file.
      write_lock.lock();

      // Check the capacity of the current active file and close it if there
      // is not enough space left for writing.
      if (active_file_) {
        if (active_file_->size + length > options_.max_file_size) {
          active_file_->CloseFile(sync);

          // Acquire exclusive access to list of data files.
          std::lock_guard file_lock(file_mutex_);
          // Move data file into the read-only set.
          files_[0].push_back(std::move(active_file_));
        }
      }

      // Create new active file if none exists.
      if (!bool(active_file_)) {
        auto [file, status] = MakeWritableFile("0-" + std::to_string(++clock_) + ".dat", false);
        if (status) {
          active_file_ = std::move(file);
        } else {
          return {file, status};
        }
      }

      return {active_file_, {}};
    };

    return WriteEntryToFile(key, value, timestamp, is_tombstone, sync, file_provider);
  }

 private:
  static uint64_t CalculateCrc(const std::span<const iovec, 3>& parts) noexcept {
    std::unique_ptr<XXH64_state_t, std::function<void(XXH64_state_t*)>> state(
        //
        XXH64_createState(),
        //
        [](XXH64_state_t* state) { XXH64_freeState(state); });

    XXH64_reset(state.get(), 0);

    for (const auto& part : parts) {
      XXH64_update(state.get(), part.iov_base, part.iov_len);
    }

    return XXH64_digest(state.get());
  }

  static Status LoadFromFile(int fd, void* buf, size_t len, size_t& off) noexcept {
    while (len) {
      int ret = ::pread(fd, buf, len, off);

      if (ret == -1) {
        return Status::IOError(errno);
      } else if (ret == 0) {
        return Status::IOError(0);
      } else {
        buf = static_cast<std::byte*>(buf) + ret;
        len -= ret;
        off += ret;
      }
    }

    return {};
  }

  static std::optional<int> ParseLayoutIndex(std::string_view name) {
    auto pos = name.find("-");
    if (pos != std::string_view::npos) {
      int num = 0;
      for (const auto c : name.substr(0, pos)) {
        if (c < '0' || c > '9') {
          return {};
        }
        num = 10 * num + (c - '0');
      }
      return num;
    }
    return {};
  }

  /// Reads full content of an entry.
  static std::tuple<size_t, Status> ReadEntryImpl(const int fd, const size_t offset, const bool check_crc,
      detail::Entry& entry, std::string& key, std::string& value) {
    size_t current_offset = offset;
    uint64_t crc;
    Status status;
    // Load crc.
    if (!(status = LoadFromFile(fd, &crc, sizeof(crc), current_offset))) {
      return {{}, status};
    }
    // Load entry.
    if (!(status = LoadFromFile(fd, &entry, sizeof(entry), current_offset))) {
      return {{}, status};
    }
    // Validate entry.
    // TODO: max_value_size
    key.resize(entry.key_size);
    value.resize(entry.value_size);
    // Load value.
    if (!(status = LoadFromFile(fd, value.data(), value.size(), current_offset))) {
      return {{}, status};
    }
    // Load key.
    if (!(status = LoadFromFile(fd, key.data(), key.size(), current_offset))) {
      return {{}, status};
    }

    // Check crc.
    if (check_crc) {
      const std::array parts{
          iovec{.iov_base = &entry, .iov_len = sizeof(entry)},
          iovec{.iov_base = value.data(), .iov_len = value.size()},
          iovec{.iov_base = key.data(), .iov_len = key.size()},
      };

      if (CalculateCrc(parts) != crc) {
        return {{}, Status::Inconsistent()};
      }
    }

    return {current_offset - offset, {}};
  }

  /// @brief Writes record to the data file provided by \p cb
  static std::pair<Record, Status> WriteEntryToFile(const std::string_view key,
      const std::string_view value, const uint64_t timestamp, const bool is_tombstone, const bool sync,
      const std::function<FileInfoStatus(size_t)>& cb) {
    assert(!is_tombstone || value.empty());

    uint64_t crc;
    // Total size of data to write.
    const size_t length = sizeof(uint64_t) + sizeof(detail::Entry) + key.size() + value.size();
    // Fill entry.
    const detail::Entry entry{
        .timestamp = timestamp,
        .flags = uint16_t(is_tombstone ? detail::kEntryFlagTombstone : 0x00),
        .key_size = uint16_t(key.size()),
        .value_size = uint32_t(value.size()),
    };
    // Make parts.
    const std::array parts = {
        iovec{.iov_base = &crc, .iov_len = sizeof(crc)},
        iovec{.iov_base = (void*)&entry, .iov_len = sizeof(entry)},
        iovec{.iov_base = (void*)value.data(), .iov_len = value.size()},
        iovec{.iov_base = (void*)key.data(), .iov_len = key.size()},
    };
    // Calculate crc.
    crc = CalculateCrc(std::span(parts).subspan<1>());

    const auto [file, status] = cb(length);
    if (!status) {
      return {{}, status};
    }
    // Offset at which new entry will be written.
    const uint64_t offset = file->size;

    const ssize_t ret = ::writev(file->fd, (struct iovec*)parts.data(), parts.size());

    if (ret == -1) {
      return {{}, Status::IOError(errno)};
    }
    if (ret != length) {
      return {{}, Status::IOError(0)};
    }
    // Force flush of written data.
    if (sync) {
      ::fsync(file->fd);
    }
    // Update size of written data.
    file->size.fetch_add(length);

    auto record = Record{
        .file = file.get(),
        .timestamp = timestamp,
        .offset = uint32_t(offset + sizeof(uint64_t) + sizeof(detail::Entry)),
        .size = uint32_t(value.size()),
    };

    return {record, {}};
  }

 private:
  struct StringHash {
    using is_transparent = void;

    size_t operator()(const std::string_view value) const noexcept {
      return std::hash<std::string_view>()(value);
    }

    size_t operator()(const std::string& value) const noexcept { return std::hash<std::string>()(value); }
  };

  template <typename V>
  using unordered_string_map = std::unordered_map<std::string, V, StringHash, std::equal_to<>>;

  Options options_;
  /// Root directory of the storage.
  std::filesystem::path base_path_;

  /// Virtual clock.  The clock is incremented by one on each update.
  std::atomic_uint64_t clock_{0};

  /// Operation mutex is used for synchronization between public operations
  /// and background merging process.
  mutable std::shared_mutex operation_mutex_;

  mutable std::shared_mutex key_mutex_;
  /// Set of actual keys.  The set does not contain tombstones.
  unordered_string_map<Record> keys_;

  /// The set contains updates of keys made during merging process.
  /// Deleted keys stored as records with timestamp equal to zero.
  std::unique_ptr<unordered_string_map<Record>> updated_keys_;

  mutable std::mutex lock_mutex_;
  mutable std::condition_variable lock_cond_;
  /// A set of fine-grained locks.
  std::unordered_set<std::string_view> key_locks_;

  /// Provides exclusive access for writing to active file.
  /// The mutex must also be taken when updating the list of data files.
  std::mutex write_mutex_;
  /// Index of a file designated for writing.
  std::shared_ptr<FileInfo> active_file_;

  mutable std::mutex file_mutex_;
  /// Ln read-only data files.
  std::vector<std::vector<std::shared_ptr<FileInfo>>> files_;
};

} // namespace bitcask
