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

// The byte size of the magic number.
static constexpr size_t kFileMagicSize = 6;
// The magic number for the first version of the data file format.
static constexpr char kFileMagicV1[] = {'B', 'C', 'S', 'K', 'V', '1'};

static constexpr uint16_t kFileFlagNone = 0x00;
static constexpr uint16_t kFileFlagWithFooter = 0x01;

static constexpr uint16_t kEntryFlagTombstone = 0x01;

// |-----------------------------------------------------------|
// |                The layout of the data record              |
// |-----------------------------------------------------|-----|
// | 64 bit | 64 bit | 32 bit   | 16 bit | 8 bit | var   | var |
// |--------|--------|----------|--------|-------|-------|-----|
// | crc    | tstamp | value_sz | key_sz | flags | value | key |
// |-----------------------------------------------------|-----|

#pragma pack(push, 1)

struct Header {
  /// Magic constant ('BCSKV1') to identify the type of the file.
  char magic[kFileMagicSize];
  /// Various flags for the data file.
  uint16_t flags;
};

struct Entry {
  /// The update time of the record.
  uint64_t timestamp;
  /// The size of the record's value.
  uint32_t value_size;
  /// The size of the record's key.
  uint16_t key_size;
  /// Various flags for the entry.
  uint8_t flags;

  constexpr bool is_tobstone() const noexcept { return (flags & kEntryFlagTombstone) != 0; }
};

struct Index {
  /// The update time of the record.
  uint64_t timestamp;
  /// The offset to the record from the begginning of the file.
  uint64_t entry_pos;
  /// The size of the record's value.
  uint32_t value_size;
  /// The size of the record's key.
  uint16_t key_size;
  /// Various flags for the entry.
  uint8_t flags;
};

struct Footer {
  /// Offset from the begginning of the file to the beginning of section with
  /// entries.
  uint64_t entries;
  /// Offset from the begginning of the file to the beginning of section with
  /// index.
  uint64_t index;
};

#pragma pack(pop)

static_assert(sizeof(kFileMagicV1) == kFileMagicSize);
static_assert(sizeof(Header) == 8);
static_assert(sizeof(Entry) == 15);
static_assert(sizeof(Index) == 23);
static_assert(sizeof(Footer) == 16);

} // namespace detail

class Status {
  enum class Code {
    kSuccess = 0,
    /// Requested entity was not found.
    kNotFound,
    /// Requested operation already in progress.
    kInProgress,
    /// Invalid argument.
    kInvalidArgument,
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

  static constexpr Status InvalidArgument() noexcept { return Status(Code::kInvalidArgument); }

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
      case Code::kInvalidArgument:
        return "Invalid argument";
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

  /// Returns true if the status indicates InvalidArgument error.
  constexpr bool IsInvalidArgument() const noexcept { return code_ == Code::kInvalidArgument; }

  /// Returns true if the status indicates a NotFound error.
  constexpr bool IsNotFound() const noexcept { return code_ == Code::kNotFound; }

  /// Returns true if the status indicates success.
  constexpr bool IsSuccess() const noexcept { return code_ == Code::kSuccess; }

  /// Returns true if the status indicates an IO error.
  constexpr bool IsIOError() const noexcept { return code_ == Code::kIOError; }

  /// Returns true if the status indicates an IO error due to too many open files.
  constexpr bool IsTooManyOpenFiles() const noexcept { return code_ == Code::kIOError && errno_ == EMFILE; }

  /// Returns true if the status indicates read-only mode.
  constexpr bool IsReadOnly() const noexcept { return code_ == Code::kReadOnly; }

  explicit constexpr operator bool() const noexcept { return IsSuccess(); }

 private:
  constexpr Status(Code code, int errnum = 0) noexcept : code_(code), errno_(errnum) {}

 private:
  Code code_{Code::kSuccess};
  /// System error number.
  int errno_{0};
};

struct Options {
  /// Number of active files.
  uint8_t active_files = 1;

  uint8_t compaction_levels = 2;

  uint32_t max_file_size = std::numeric_limits<uint32_t>::max();

  /// Flush in-core data to storage device after write.
  bool data_sync = false;

  /// If true, the store will be opened in read-only mode.
  bool read_only = false;

  /// Write index at the end of each merged file.
  bool write_index = true;
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

    /// Total size of the file.
    /// The size is only updated on writing or set on loading.
    std::atomic_uint64_t size{0};

    /// Number of records with a value.
    std::atomic_uint64_t records{0};
    /// Number of obsolete records. The obsolete record is a record that has been replaced by another
    /// record with the same key or by a tombstone.
    std::atomic_uint64_t obsolete{0};
    /// Number of tombstones.
    std::atomic_uint64_t tombstones{0};

   public:
    FileInfo(std::filesystem::path p, uint64_t s) noexcept : path(std::move(p)), size(s) {}

#ifndef NDEBUG
    ~FileInfo() {
      // Check there are no leaks of file descriptors.
      assert(fd == -1);
    }
#endif

    /**
     * Appends data to the file.
     *
     * @param parts scatter parts of the data to write.
     * @param sync if true, fsync will be called after write.
     */
    Status Append(const std::span<const iovec>& parts, const bool sync) noexcept {
      const size_t length = std::accumulate(
          parts.begin(), parts.end(), 0ul, [](const auto acc, const auto& p) { return acc + p.iov_len; });

      const ssize_t ret = ::writev(fd, parts.data(), parts.size());
      // Write errors.
      if (ret == -1) {
        return Status::IOError(errno);
      }
      if (ret != length) {
        return Status::IOError(0);
      }
      // Force flush of written data.
      if (sync) {
        ::fsync(fd);
      }
      // Update total size of the file.
      size.fetch_add(length);

      return {};
    }

    /**
     * Waits for the completion of all ongoing reads and closes the file descriptor.
     *
     * @param sync if true, fsync will be called before the file is closed.
     *
     * @returns true if the file descriptor is valid and has been closed; otherwise, it returns false.
     */
    bool CloseFile(bool sync = false) {
      int prev_fd = -1;

      {
        // Wait until all possible readings from the file have been completed.
        std::lock_guard read_lock(read_mutex);
        // Acquire exclusive access to file descriptor.
        std::lock_guard fd_lock(fd_mutex);

        // Check file is opened.
        if (fd == -1) {
          return false;
        }
        // After resetting the file descriptor, a concurrent thread can open the
        // file for reading.
        std::swap(fd, prev_fd);
      }

      // Flush data if needed.
      if (sync) {
        ::fsync(prev_fd);
      }
      // Close the file descriptor.
      ::close(prev_fd);

      return true;
    }

    /**
     * Checks file is opened otherwise opens it in read-only mode.
     */
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

  struct FileSections {
    using Range = std::pair<uint64_t, uint64_t>;

    std::optional<Range> header;
    std::optional<Range> entries;
    std::optional<Range> index;
    std::optional<Range> footer;
  };

  struct Record {
    /// Data file contained the record.
    FileInfo* file;
    /// Time the record was written.
    uint64_t timestamp;
    /// Offset to the beginning of the record within the data file.
    uint32_t offset;
    /// Size of the value.
    uint32_t size;
  };

  static_assert(std::is_trivial_v<Record>);
  static_assert(sizeof(Record) == sizeof(void*) + 16);

  using FileInfoStatus = std::pair<std::shared_ptr<FileInfo>, Status>;

 public:
  ~Database() {
    // Close writable files.
    for (const auto& item : active_files_) {
      if (item.file) {
        item.file->CloseFile(options_.data_sync);
      }
    }
    // Close read-only files.
    for (const auto& parts : files_) {
      std::for_each(parts.begin(), parts.end(), [this](const auto& f) { f->CloseFile(); });
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

    std::unique_lock key_lock(key_mutex_);
    // Update key-set
    if (updated_keys_) {
      const bool present_in_main = keys_.contains(key);
      // During the merging process only the updated_keys_ can be modified.
      if (auto ki = updated_keys_->find(key); ki != updated_keys_->end()) {
        ki->second.file->obsolete.fetch_add(1);
        if (present_in_main) {
          ki->second = Record{};
        } else {
          updated_keys_->erase(ki);
        }
      } else if (present_in_main) {
        updated_keys_->emplace(std::string(key), Record{});
      }
    } else {
      if (auto ki = keys_.find(key); ki != keys_.end()) {
        ki->second.file->obsolete.fetch_add(1);
        keys_.erase(ki);
      }
    }

    return {};
  }

  void Enumerate(const std::function<void(const std::string_view)>& cb) const {
    std::shared_lock op_lock(operation_mutex_);
    std::shared_lock key_lock(key_mutex_);

    for (const auto& [key, _] : keys_) {
      cb(key);
    }
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
      if (value) {
        return ReadValue(options, *record, *value);
      } else {
        return Status::Success();
      }
    }

    return Status::NotFound();
  }

  /// Put an object into the database.
  Status Put(const WriteOptions& options, const std::string_view key, const std::string_view value) {
    std::shared_lock op_lock(operation_mutex_);

    if (key.size() > std::numeric_limits<decltype(detail::Entry::key_size)>::max()) {
      return Status::InvalidArgument();
    }
    if (value.size() > std::numeric_limits<decltype(detail::Entry::value_size)>::max()) {
      return Status::InvalidArgument();
    }
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

    std::unique_lock key_lock(key_mutex_);
    // Update key-set
    if (updated_keys_) {
      // During the merging process only the updated_keys_ can be modified.
      if (auto ki = updated_keys_->find(key); ki == keys_.end()) {
        updated_keys_->emplace(key, record);
      } else {
        ki->second.file->obsolete.fetch_add(1);
        ki->second = record;
      }

    } else {
      if (auto ki = keys_.find(key); ki == keys_.end()) {
        keys_.emplace(key, record);
      } else {
        ki->second.file->obsolete.fetch_add(1);
        ki->second = record;
      }
    }

    return {};
  }

 public:
  /**
   * Closes all opened read-only files.
   */
  void CloseFiles() {
    std::lock_guard file_lock(file_mutex_);

    for (const auto& parts : files_) {
      std::for_each(parts.begin(), parts.end(), [this](const auto& f) { f->CloseFile(); });
    }
  }

  Status Pack(bool force = false) {
    for (size_t i = 0; i != compaction_slots_count_; ++i) {
      std::vector<std::shared_ptr<FileInfo>> files;
      CompactionMode mode;

      {
        std::unique_lock op_lock(operation_mutex_);

        // Check whether the compaction process is already in progress.
        if (updated_keys_) {
          return Status::InProgress();
        }

        std::lock_guard file_lock(file_mutex_);
        // No more slots to process. Done.
        if (i == files_.size()) {
          return {};
        }
        // Check if there is something to process.
        if (files_[i].empty()) {
          continue;
        }
        if (IsLastCompactionLevel(i)) {
          if (!force && files_[i].size() < 4) {
            continue;
          }
          mode = CompactionMode::kGather;
        } else if (i == 0) {
          mode = CompactionMode::kScatter;
        } else {
          // Total size of the files in the slot.
          const size_t total_size = std::accumulate(files_[i].begin(), files_[i].end(), 0ull,
              [](const auto acc, const auto& f) { return acc + f->size; });

          if (total_size > options_.max_file_size) {
            mode = CompactionMode::kScatter;
          } else {
            bool process = false;

            for (size_t j = 0, end = files_[i].size(); j != end; ++j) {
              const auto records = files_[i][j]->records.load();
              const auto obsolete = files_[i][j]->obsolete.load();

              if (records == 0) {
                continue;
              }
              if (double(obsolete) / double(records) > 0.5) {
                process = true;
                break;
              }
            }

            if (!process && !force && files_[i].size() < 4) {
              continue;
            }
            mode = CompactionMode::kGather;
          }
        }

        // Grab all accumulated files for processing.
        files.swap(files_[i]);

        // Create a key-set for buffering updates during the merge.
        updated_keys_ = std::make_unique<unordered_string_map<Record>>();
      }

      auto status = PackFiles(files, mode, i);

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

      if (status) {
        // Cleanup processed files.
        for (const auto& file : files) {
          assert(file.use_count() == 1);

          file->CloseFile();
          // Remove processed file from the storage device.
          std::filesystem::remove(file->path);
        }
      } else {
        std::lock_guard file_lock(file_mutex_);

        files_[i].insert(
            files_[i].end(), std::make_move_iterator(files.begin()), std::make_move_iterator(files.end()));

        return status;
      }
    }

    return {};
  }

  /// Closes current active files.
  Status Rotate() {
    std::shared_lock op_lock(operation_mutex_);
    std::vector<std::shared_ptr<FileInfo>> files;

    if (options_.read_only) {
      return Status::ReadOnly();
    }

    for (auto& item : active_files_) {
      // Acquire exclusive access for writing to active file.
      std::lock_guard write_lock(item.write_mutex);
      // Check if there is a file opened for writing.
      if (item.file) {
        files.push_back(std::move(item.file));
      }
    }

    // Close files for writing.
    for (const auto& f : files) {
      f->CloseFile(options_.data_sync);
    }
    // Acquire exclusive access to the list of data files.
    std::lock_guard file_lock(file_mutex_);
    // Move data files into the read-only set.
    files_[0].insert(
        files_[0].end(), std::make_move_iterator(files.begin()), std::make_move_iterator(files.end()));

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
      : options_(options), base_path_(path), active_files_(std::max<unsigned>(1u, options.active_files)) {
    // Calculate number of slots for an LSM-tree with up to 8 nodes per level, starting with the second.
    compaction_slots_count_ = ((1ull << (3 * (options_.compaction_levels + 1))) - 1) / 7;

    // Allocate compaction slots.
    files_.resize(compaction_slots_count_);

    compaction_levels_.resize(options_.compaction_levels + 1);
    // Fill ranges of compaction levels.
    for (int i = 1, end = options_.compaction_levels + 1; i != end; ++i) {
      compaction_levels_[i].first = (compaction_levels_[i - 1].first * 8) + 1;
      compaction_levels_[i].second = (compaction_levels_[i - 1].second + 1) * 8;
    }
  }

  Status Initialize() {
    unordered_string_map<uint64_t> tombstones;

    const auto cb = [&](const Record& record, const bool is_tombstone, std::string_view key) -> Status {
      clock_ = std::max<uint64_t>(clock_, record.timestamp);
      // Count entries.
      if (is_tombstone) {
        record.file->tombstones.fetch_add(1);
      } else {
        record.file->records.fetch_add(1);
      }

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
            ki->second.file->obsolete.fetch_add(1);
            keys_.erase(ki);
          }
        }

        return {};
      }

      // The record will be deleted in the future. Skip it.
      if (ti != tombstones.end() && record.timestamp < ti->second) {
        record.file->obsolete.fetch_add(1);
        return {};
      }

      if (const auto ki = keys_.find(key); ki == keys_.end()) {
        keys_.emplace(key, record);
      } else if (ki->second.timestamp < record.timestamp) {
        ki->second.file->obsolete.fetch_add(1);
        ki->second = record;
      }

      return {};
    };

    const auto enumerate_keys = [this](const auto& file, const auto& cb) {
      FileSections sections;

      if (auto s = LoadFileSections(file, &sections); !s) {
        return s;
      }

      if (sections.index) {
        return EnumerateIndex(file, sections.index.value(), cb);
      } else {
        return EnumerateEntries(file, sections.entries.value(),
            [&](const Record& record, const bool is_tombstone, std::string_view key, std::string_view) {
              return cb(record, is_tombstone, key);
            });
      }
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
      // Read keys from the file.
      if (auto s = enumerate_keys(file, cb); !s) {
        if (s.IsNotFound()) {
          continue;
        }
        return s;
      }

      // Move data file into the read-only set.
      if (index.value() >= compaction_slots_count_) {
        files_[0].push_back(std::move(file));
      } else {
        files_[index.value()].push_back(std::move(file));
      }
    }
    return {};
  }

  bool IsLastCompactionLevel(const size_t i) const noexcept {
    return i >= compaction_levels_.back().first && i <= compaction_levels_.back().second;
  };

  Status PackFiles(
      const std::vector<std::shared_ptr<FileInfo>>& files, const CompactionMode mode, const int slot) {
    std::vector<std::vector<std::shared_ptr<FileInfo>>> output(8);
    std::vector<std::pair<decltype(keys_)::iterator, Record>> updates;

    static_assert(std::is_trivially_destructible_v<decltype(updates)::value_type>);

    const auto cb = [&](const Record& record, const bool is_tombstone, const std::string_view key,
                        const std::string_view value) -> Status {
      auto ki = keys_.find(key);
      if (ki == keys_.end()) {
        if (is_tombstone) {
          if (IsLastCompactionLevel(slot)) {
            assert(mode == CompactionMode::kGather);
            return {};
          }
        } else {
          // Old key that has already been deleted. Do not retain.
          return {};
        }
      } else if (ki->second.timestamp == record.timestamp) {
        // The current value or potential data duplication. Keep only the current one.
        if (ki->second.file != record.file || ki->second.offset != record.offset) {
          return {};
        }
      } else {
        assert(ki->second.timestamp > record.timestamp);
        return {};
      }

      const auto [rec, status] = WriteEntryToFile(key, value, record.timestamp, is_tombstone, false,
          // Target file provider.
          [&](const uint64_t length) -> FileInfoStatus {
            size_t i = 0;
            size_t index = slot;

            if (mode == CompactionMode::kScatter) {
              i = XXH64(key.data(), key.size(), slot + 1) % 8;
              index = (slot * 8 + 1) + i;
            }

            if (output[i].empty() || IsCapacityExceeded(output[i].back()->size, length)) {
              auto [file, status] = MakeWritableFile(
                  std::to_string(index) + "-" + std::to_string(++clock_) + ".dat", options_.write_index);
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

    // 1. Process input files.
    for (const auto& file : files) {
      // Acquiring read lock to prevent closing the file handle during the read.
      std::shared_lock read_lock(file->read_mutex);

      // Ensure source file is opened.
      if (auto s = file->EnsureReadable(); !s) {
        return s;
      }
      // Enumerate all records in the source file.
      if (auto s = EnumerateEntriesNoLock(file, cb); !s) {
        read_lock.unlock();
        // TODO: finalize.
        return s;
      }
    }

    // 2. Finalize output files.
    for (size_t i = 0, end = output.size(); i != end; ++i) {
      const auto& f = output[i];

      std::for_each(f.begin(), f.end(), [this](auto& f) {
        // Append index at the end of file.
        if (options_.write_index) {
          WriteIndex(f); // TODO: handle errors.
        }
        // Ensure that all data has been written to the storage device
        // before deleting the source files.
        f->CloseFile(true);
      });
    }

    // 3. Assign new location for the entries read from the input files.
    if (updates.size()) {
      std::lock_guard key_lock(key_mutex_);

      for (const auto& [ki, record] : updates) {
        ki->second = record;
      }
    }

    std::lock_guard file_lock(file_mutex_);
    // 4. Append output files to LSM-tree.
    for (size_t i = 0, end = output.size(); i != end; ++i) {
      files_[1 + i].insert(files_[1 + i].end(), output[i].begin(), output[i].end());
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
      lock->lock();
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
  void WaitKeyUnlocked(const std::string_view key, std::shared_lock<std::shared_mutex>& lock) const {
    std::unique_lock lock_lock(lock_mutex_);

    // Wait the key will be unlocked by a concurent thread.
    while (key_locks_.contains(key)) {
      lock_cond_.wait(lock_lock);
    }

    lock.lock();
  }

 private:
  Status EnumerateIndex(const std::shared_ptr<FileInfo>& file, const FileSections::Range& range,
      const std::function<Status(const Record&, const bool, std::string_view)>& cb) const {
    const auto fd = file->fd;
    std::string key;

    for (size_t offset = range.first, end = range.second; offset < end;) {
      uint64_t crc;
      detail::Index index;
      Status status;
      // Load crc.
      if (!(status = LoadFromFile(fd, &crc, sizeof(crc), offset))) {
        return status;
      }
      // Load entry.
      if (!(status = LoadFromFile(fd, &index, sizeof(index), offset))) {
        return status;
      }
      key.resize(index.key_size);
      // Load key.
      if (!(status = LoadFromFile(fd, key.data(), key.size(), offset))) {
        return status;
      }
      // Check crc.
      const std::array parts{
          iovec{.iov_base = &index, .iov_len = sizeof(index)},
          iovec{.iov_base = key.data(), .iov_len = key.size()},
      };
      if (Hash64(std::span(parts)) != crc) {
        return Status::Inconsistent();
      }

      const Record record{
          .file = file.get(),
          .timestamp = index.timestamp,
          .offset = uint32_t(index.entry_pos),
          .size = index.value_size,
      };

      if (!(status = cb(record, index.flags & detail::kEntryFlagTombstone, key))) {
        return status;
      }
    }

    return {};
  }

  Status EnumerateEntries(const std::shared_ptr<FileInfo>& file, const FileSections::Range& range,
      const std::function<Status(const Record&, const bool, std::string_view, std::string_view)>& cb)
      const {
    const auto fd = file->fd;
    std::string key;
    std::string value;

    for (size_t offset = range.first, end = range.second; offset < end;) {
      detail::Entry e;

      auto [read, status] = ReadEntryImpl(file->fd, offset, false, e, key, value);
      if (!status) {
        return status;
      }

      const Record record{
          .file = file.get(),
          .timestamp = e.timestamp,
          .offset = uint32_t(offset),
          .size = uint32_t(value.size()),
      };

      auto s = cb(record, (e.flags & detail::kEntryFlagTombstone), key, value);
      if (!s) {
        return s;
      }

      offset += read;
    }

    return {};
  }

  Status EnumerateEntriesNoLock(const std::shared_ptr<FileInfo>& file,
      const std::function<Status(const Record&, const bool, std::string_view, std::string_view)>& cb)
      const {
    FileSections sections;

    if (auto s = LoadFileSections(file, &sections); !s) {
      return s;
    }

    return EnumerateEntries(file, sections.entries.value(), cb);
  }

  /**
   * Checks whether the appending block would exceed the file's capacity.
   *
   * @param current_size current size of a file.
   * @param length length of the block to be appended.
   * @returns true if the block exceeds capacity, false otherwise.
   */
  bool IsCapacityExceeded(const uint64_t current_size, const uint64_t length) const noexcept {
    static constinit auto kMaxEntryOffset = std::numeric_limits<decltype(Record::offset)>::max();

    return
        // Ensure that the offset of the value does not overflow.
        (current_size) > kMaxEntryOffset ||
        // Ensure that the limit of the file size will not be exceeded.
        (current_size + length > options_.max_file_size);
  }

  /**
   * Creates a writable file object.
   *
   * @param name name of the data file.
   * @param with_footer set the flag signaling of footer's presence at the end of the file.
   *
   * @returns a writable file object or an error status code.
   */
  FileInfoStatus MakeWritableFile(const std::string& name, bool with_footer) const {
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
          .flags = with_footer ? detail::kFileFlagWithFooter : detail::kFileFlagNone};

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
    if (auto s = record.file->EnsureReadable(); !s) {
      return s;
    }

    if (options.verify_checksums) {
      size_t offset = record.offset;
      detail::Entry e;
      std::string key;
      return std::get<1>(ReadEntryImpl(record.file->fd, offset, true, e, key, value));
    } else {
      size_t offset = record.offset + (sizeof(uint64_t) + sizeof(detail::Entry));
      // Allocate memory for the value.
      value.resize(record.size);
      // Load value.
      return LoadFromFile(record.file->fd, value.data(), value.size(), offset);
    }
  }

  /**
   * Writes the data to the active data file.
   *
   * @returns written record or an error code if the write was unseccessful.
   */
  std::pair<Record, Status> WriteEntry(const std::string_view key, const std::string_view value,
      const uint64_t timestamp, const bool is_tombstone, const bool sync) {
    ActiveFile& active_file = active_files_.size() == 1
                                  ? active_files_[0]
                                  : active_files_[XXH64(key.data(), key.size(), 0) % active_files_.size()];

    std::unique_lock write_lock(active_file.write_mutex, std::defer_lock);
    // Target file provider.
    const auto file_provider = [&](const uint64_t length) -> FileInfoStatus {
      // Acquire exclusive access for writing to active file.
      write_lock.lock();

      // Check the capacity of the current active file and close it if there
      // is not enough space left for writing.
      if (active_file.file) {
        if (IsCapacityExceeded(active_file.file->size, length)) {
          active_file.file->CloseFile(sync);

          // Acquire exclusive access to list of data files.
          std::lock_guard file_lock(file_mutex_);
          // Move data file into the read-only set.
          files_[0].push_back(std::move(active_file.file));
        }
      }

      // Create new active file if none exists.
      if (!bool(active_file.file)) {
        auto [file, status] = MakeWritableFile("0-" + std::to_string(++clock_) + ".dat", false);
        if (status) {
          active_file.file = std::move(file);
        } else {
          return {file, status};
        }
      }

      return {active_file.file, {}};
    };

    return WriteEntryToFile(key, value, timestamp, is_tombstone, sync, file_provider);
  }

  Status WriteIndex(const std::shared_ptr<FileInfo>& file) {
    const auto cb = [&](const Record& rec, const bool is_tombstone, const std::string_view key,
                        const std::string_view) -> Status {
      uint64_t crc;
      const detail::Index index{
          .timestamp = rec.timestamp,
          .entry_pos = uint32_t(rec.offset),
          .value_size = rec.size,
          .key_size = uint16_t(key.size()),
          .flags = uint8_t(is_tombstone ? detail::kEntryFlagTombstone : 0),
      };

      const std::array parts = {
          iovec{.iov_base = &crc, .iov_len = sizeof(crc)},
          iovec{.iov_base = (void*)&index, .iov_len = sizeof(index)},
          iovec{.iov_base = (void*)key.data(), .iov_len = key.size()},
      };

      crc = Hash64(std::span(parts).subspan<1>());

      return file->Append(parts, false);
    };

    detail::Footer footer{.entries = sizeof(detail::Header), .index = file->size.load()};
    // Write index entries.
    auto s = EnumerateEntries(file, std::make_pair(sizeof(detail::Header), file->size.load()), cb);
    if (!s) {
      return s;
    }
    // Write footer.
    return file->Append(std::array{iovec{.iov_base = &footer, .iov_len = sizeof(footer)}}, false);
  }

 private:
  template <size_t N>
  static uint64_t Hash64(const std::span<const iovec, N>& parts) noexcept {
    std::unique_ptr<XXH64_state_t, std::function<void(XXH64_state_t*)>> state(
        // Create state.
        XXH64_createState(),
        // State destructor.
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

  static Status LoadFileSections(const std::shared_ptr<FileInfo>& file, FileSections* sections) {
    detail::Header header;
    size_t offset = 0;
    // Load header.
    if (auto s = LoadFromFile(file->fd, &header, sizeof(header), offset); !s) {
      return s;
    } else if (std::memcmp(header.magic, detail::kFileMagicV1, detail::kFileMagicSize) != 0) {
      return Status::NotFound();
    }
    // Load footer.
    if (header.flags & detail::kFileFlagWithFooter) {
      detail::Footer footer;
      size_t footer_offset = file->size - sizeof(footer);
      if (auto s = LoadFromFile(file->fd, &footer, sizeof(footer), footer_offset); !s) {
        return s;
      }
      if (footer.entries > footer.index) {
        return Status::Inconsistent();
      }

      sections->header = std::pair{0, sizeof(header)};
      sections->entries = std::pair{footer.entries, footer.index};
      sections->index = std::pair{footer.index, file->size - sizeof(footer)};
      sections->footer = std::pair{file->size - sizeof(footer), file->size.load()};
    } else {
      sections->header = std::pair{0, sizeof(header)};
      sections->entries = std::pair{sizeof(header), file->size.load()};
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

      if (Hash64(std::span(parts)) != crc) {
        return {{}, Status::Inconsistent()};
      }
    }

    return {current_offset - offset, {}};
  }

  /// @brief Writes record to the data file provided by \p cb
  static std::pair<Record, Status> WriteEntryToFile(const std::string_view key,
      const std::string_view value, const uint64_t timestamp, const bool is_tombstone, const bool sync,
      const std::function<FileInfoStatus(uint64_t)>& cb) {
    assert(!is_tombstone || value.empty());

    uint64_t crc;
    // Fill entry.
    const detail::Entry entry{
        .timestamp = timestamp,
        .value_size = uint32_t(value.size()),
        .key_size = uint16_t(key.size()),
        .flags = uint8_t(is_tombstone ? detail::kEntryFlagTombstone : 0x00),
    };
    // Make parts.
    const std::array parts = {
        iovec{.iov_base = &crc, .iov_len = sizeof(crc)},
        iovec{.iov_base = (void*)&entry, .iov_len = sizeof(entry)},
        iovec{.iov_base = (void*)value.data(), .iov_len = value.size()},
        iovec{.iov_base = (void*)key.data(), .iov_len = key.size()},
    };
    // Total size of data to write.
    const uint64_t length = std::accumulate(
        parts.begin(), parts.end(), 0ull, [](const auto acc, const auto& p) { return acc + p.iov_len; });
    // Calculate crc.
    crc = Hash64(std::span(parts).subspan<1>());

    const auto [file, status] = cb(length);
    if (!status) {
      return {{}, status};
    }
    // Offset at which new entry will be written.
    const uint64_t offset = file->size;
    // Write data to the file.
    if (auto status = file->Append(parts, sync); !status) {
      return {{}, status};
    }

    // Count entries.
    if (is_tombstone) {
      file->tombstones.fetch_add(1);
    } else {
      file->records.fetch_add(1);
    }

    const Record record{
        .file = file.get(),
        .timestamp = timestamp,
        .offset = uint32_t(offset),
        .size = uint32_t(value.size()),
    };

    return {record, {}};
  }

 private:
  struct ActiveFile {
    /// Provides exclusive access for writing to the active file.
    std::mutex write_mutex;
    /// A file object designated for writing.
    std::shared_ptr<FileInfo> file;
  };

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

  /// A list of active files that can be opened simultaneously.
  std::vector<ActiveFile> active_files_;

  /// The maximum number of LSMT slots available.
  size_t compaction_slots_count_{1};
  /// Ranges of compaction levels.
  std::vector<std::pair<size_t, size_t>> compaction_levels_;

  mutable std::mutex file_mutex_;
  /// Ln read-only data files.
  std::vector<std::vector<std::shared_ptr<FileInfo>>> files_;
};

} // namespace bitcask
