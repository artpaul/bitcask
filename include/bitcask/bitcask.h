#pragma once

#include <atomic>
#include <cassert>
#include <condition_variable>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct iovec;

namespace bitcask {

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

  std::string Message() const;

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
    Status Append(const std::span<const iovec>& parts, const bool sync) noexcept;

    /**
     * Waits for the completion of all ongoing reads and closes the file descriptor.
     *
     * @param sync if true, fsync will be called before the file is closed.
     *
     * @returns true if the file descriptor is valid and has been closed; otherwise, it returns false.
     */
    bool CloseFile(bool sync = false);

    /**
     * Checks file is opened otherwise opens it in read-only mode.
     */
    Status EnsureReadable();
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
  ~Database();

  static Status Open(
      const Options& options, const std::filesystem::path& path, std::unique_ptr<Database>& db);

 public:
  Status Delete(const WriteOptions& options, const std::string_view key);

  void Enumerate(const std::function<void(const std::string_view)>& cb) const;

  Status Get(const ReadOptions& options, const std::string_view key, std::string* value) const;

  /// Put an object into the database.
  Status Put(const WriteOptions& options, const std::string_view key, const std::string_view value);

 public:
  /**
   * Closes all opened read-only files.
   */
  void CloseFiles();

  Status Pack(bool force = false);

  /// Closes current active files.
  Status Rotate();

 private:
  Database(const Options& options, const std::filesystem::path& path);

  Status Initialize();

  bool IsLastCompactionLevel(const size_t i) const noexcept;

  Status PackFiles(
      const std::vector<std::shared_ptr<FileInfo>>& files, const CompactionMode mode, const int slot);

 private:
  std::optional<Record> GetKeyNoLock(const std::string_view key) const;

  /// Sets lock to individual key.
  void LockKey(const std::string_view key, std::shared_lock<std::shared_mutex>* lock);

  /// Unlock an individual key.
  void UnlockKey(const std::string_view key);

  /// Waits individual key will be unlocked.
  void WaitKeyUnlocked(const std::string_view key, std::shared_lock<std::shared_mutex>& lock) const;

 private:
  Status EnumerateIndex(const std::shared_ptr<FileInfo>& file, const FileSections::Range& range,
      const std::function<Status(const Record&, const bool, std::string_view)>& cb) const;

  Status EnumerateEntries(const std::shared_ptr<FileInfo>& file, const FileSections::Range& range,
      const std::function<Status(const Record&, const bool, std::string_view, std::string_view)>& cb) const;

  Status EnumerateEntriesNoLock(const std::shared_ptr<FileInfo>& file,
      const std::function<Status(const Record&, const bool, std::string_view, std::string_view)>& cb) const;

  /**
   * Checks whether the appending block would exceed the file's capacity.
   *
   * @param current_size current size of a file.
   * @param length length of the block to be appended.
   * @returns true if the block exceeds capacity, false otherwise.
   */
  bool IsCapacityExceeded(const uint64_t current_size, const uint64_t length) const noexcept;

  /**
   * Creates a writable file object.
   *
   * @param name name of the data file.
   * @param with_footer set the flag signaling of footer's presence at the end of the file.
   *
   * @returns a writable file object or an error status code.
   */
  FileInfoStatus MakeWritableFile(const std::string& name, bool with_footer) const;

  Status ReadValue(const ReadOptions& options, const Record& record, std::string& value) const;

  /**
   * Writes the data to the active data file.
   *
   * @returns written record or an error code if the write was unseccessful.
   */
  std::pair<Record, Status> WriteEntry(const std::string_view key, const std::string_view value,
      const uint64_t timestamp, const bool is_tombstone, const bool sync);

  Status WriteIndex(const std::shared_ptr<FileInfo>& file);

 private:
  static Status LoadFileSections(const std::shared_ptr<FileInfo>& file, FileSections* sections);

  static std::optional<int> ParseLayoutIndex(std::string_view name);

  /// @brief Writes record to the data file provided by \p cb
  static std::pair<Record, Status> WriteEntryToFile(const std::string_view key,
      const std::string_view value, const uint64_t timestamp, const bool is_tombstone, const bool sync,
      const std::function<FileInfoStatus(uint64_t)>& cb);

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
