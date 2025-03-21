#pragma once

#include <atomic>
#include <cassert>
#include <condition_variable>
#include <filesystem>
#include <functional>
#include <future>
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

enum class FlushMode {
  kNone = 0,
  /// Flush in-core data only when closing an active file.
  kOnClose,
  /// Delay flushing of the written data.
  kDelay,
  /// Flush in-core data after each write.
  kImmediately,
};

struct Options {
  /// Number of active files.
  uint8_t active_files = 1;

  /// Mode of flushing written in-core data to storage device.
  FlushMode flush_mode = FlushMode::kNone;

  std::optional<FlushMode> flush_mode_for_delete = {};

  std::chrono::nanoseconds flush_delay = std::chrono::milliseconds(1);

  uint32_t max_file_size = std::numeric_limits<uint32_t>::max();

  uint8_t compaction_levels = 2;

  /// If the database has been loaded successfully, clean up any temporary files at startup.
  bool clean_temporary_on_startup = true;

  /// Preallocate output files.
  bool preallocate = false;

  /// If true, the store will be opened in read-only mode.
  bool read_only = false;

  /// Limit speed of compaction process.
  bool throttle_compaction = false;

  /// Write index at the end of each merged file.
  bool write_index = true;
};

struct Range {
  uint32_t offset;
  uint32_t size;
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

  /// Subrange of the value to read.
  std::optional<Range> range{};
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

  struct FileInfo;
  struct WaitQueue;

  struct ActiveFile {
    /// Provides exclusive access for writing to the active file.
    std::mutex write_mutex;
    /// A file object designated for writing.
    std::shared_ptr<FileInfo> file;

    std::chrono::steady_clock::time_point last_write;
    // Wait queue for delayed flushes.
    std::weak_ptr<WaitQueue> wait_queue;

   public:
    std::error_code FlushWithDelay(
        const std::chrono::nanoseconds delay, std::unique_lock<std::mutex> write_lock);

    bool MaybeFlushImmediately(const std::chrono::nanoseconds delay);
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
    /// The file may have partially written record at the end.
    const bool may_have_uncommitted;

    /// Total size of the file.
    /// The size is only updated on writing or set on loading.
    uint64_t size{0};

    /// Number of records with a value.
    std::atomic_uint64_t records{0};
    /// Number of obsolete records. The obsolete record is a record that has been replaced by another
    /// record with the same key or by a tombstone.
    std::atomic_uint64_t obsolete{0};
    /// Number of tombstones.
    std::atomic_uint64_t tombstones{0};

   public:
    FileInfo(std::filesystem::path p, uint64_t s, bool uncommitted) noexcept
        : path(std::move(p)), may_have_uncommitted(uncommitted), size(s) {}

#ifndef NDEBUG
    ~FileInfo() {
      // Check there are no leaks of file descriptors.
      assert(fd == -1);
    }
#endif

    /**
     * Allocate disk space for the output file.
     *
     * @param size number of bytes to allocate.
     */
    std::error_code Allocate(const uint64_t size) noexcept;

    /**
     * Appends data to the file.
     *
     * @param parts scatter parts of the data to write.
     * @param sync if true, fsync will be called after write.
     */
    std::error_code Append(const std::span<const iovec>& parts, const bool sync) noexcept;

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
    std::error_code EnsureReadable();

    /**
     * @brief Truncates the file to the actual size if the file is opened.
     */
    std::error_code Truncate() noexcept;
  };

  struct WaitQueue {
    std::condition_variable cond;
    std::promise<std::error_code> promise;
    std::shared_future<std::error_code> result;

   public:
    WaitQueue() : result(promise.get_future()) {}
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

  using FileInfoStatus = std::pair<std::shared_ptr<FileInfo>, std::error_code>;

 public:
  ~Database();

  static std::error_code Open(
      const Options& options, const std::filesystem::path& path, std::unique_ptr<Database>& db);

 public:
  /**
   * Deletes an object from the database.
   *
   * @param key key of the object to delete.
   */
  std::error_code Delete(const WriteOptions& options, const std::string_view key);

  /**
   * Lists all objects in the database.
   */
  void Enumerate(const std::function<void(const std::string_view)>& cb) const;

  /**
   * Reads an object from the database.
   *
   * @param key key of the object to read.
   */
  std::error_code Get(const ReadOptions& options, const std::string_view key, std::string* value) const;

  /**
   * Puts an object into the database.
   *
   * @param key key of the object to add.
   */
  std::error_code Put(
      const WriteOptions& options, const std::string_view key, const std::string_view value);

 public:
  /**
   * @Approximate value of the space occupied by data files.
   */
  uint64_t ApproximateSpaceUsed() const noexcept;

  /**
   * Closes all opened read-only files.
   */
  void CloseFiles();

  std::error_code Pack(bool force = false);

  /**
   * Closes current active files.
   */
  std::error_code Rotate();

 private:
  Database(const Options& options, const std::filesystem::path& path);

  std::error_code Initialize();

  bool IsLastCompactionLevel(const size_t i) const noexcept;

  std::error_code PackFiles(
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
  /**
   * Enumerates all keys in a file.
   *
   * @param file a file to enumerate.
   */
  std::error_code EnumerateKeys(const std::shared_ptr<FileInfo>& file,
      const std::function<std::error_code(const Record&, const bool, std::string_view)>& cb) const;

  std::error_code EnumerateIndex(const std::shared_ptr<FileInfo>& file, const FileSections::Range& range,
      const std::function<std::error_code(const Record&, const bool, std::string_view)>& cb) const;

  /**
   * Enumerates all entries in a file.
   *
   * @param file a file to enumerate.
   */
  std::error_code EnumerateEntries(const std::shared_ptr<FileInfo>& file, const FileSections::Range& range,
      const bool read_values,
      const std::function<std::error_code(const Record&, const bool, std::string_view, std::string_view)>&
          cb) const;

  ActiveFile& GetActiveFileNoLock(const std::string_view key, bool is_delete) noexcept;

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

  /**
   * Reads a value.
   */
  std::error_code ReadValue(const ReadOptions& options, const Record& record, std::string& value) const;

  /**
   * Copies a record from source file to a data file provided by \p cb
   *
   * @param fd source file.
   * @param offset offset of the record to copy.
   * @param cb file provider.
   *
   * @returns Descriptor of the written record or an error code if the write was unsuccessful.
   */
  std::pair<Record, std::error_code> CopyEntry(
      const int fd, const size_t offset, const std::function<FileInfoStatus(uint64_t)>& cb);

  ActiveFile& GetActiveFileNoLock(const std::string_view key) noexcept;

  /**
   * Writes a record to the active data file.
   *
   * @returns Descriptor of the written record or an error code if the write was unsuccessful.
   */
  std::pair<Record, std::error_code> WriteEntry(const std::string_view key, const std::string_view value,
      const uint64_t timestamp, const bool is_tombstone, const FlushMode flush_mode,
      ActiveFile& active_file);

  /**
   * Writes a record to a data file provided by \p cb
   *
   * @returns Descriptor of the written record or an error code if the write was unsuccessful.
   */
  std::pair<Record, std::error_code> WriteEntryToFile(const std::string_view key,
      const std::string_view value, const uint64_t timestamp, const bool is_tombstone, const bool sync,
      const std::function<FileInfoStatus(uint64_t)>& cb);

  /**
   * Appends index to the end of file.
   */
  std::error_code WriteIndex(const std::shared_ptr<FileInfo>& file);

 private:
  static std::error_code LoadFileSections(const std::shared_ptr<FileInfo>& file, FileSections* sections);

  static std::optional<int> ParseLayoutIndex(std::string_view name);

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

  /// A list of active files that can be opened simultaneously.
  std::vector<ActiveFile> active_files_;
  /// Dedicated file for deletes.
  std::optional<ActiveFile> active_file_for_deletes_;

  /// The maximum number of LSMT slots available.
  size_t compaction_slots_count_{1};
  /// Ranges of compaction levels.
  std::vector<std::pair<size_t, size_t>> compaction_levels_;
  /// Indication of active compaction process.
  std::atomic_bool compaction_is_active_{false};

  mutable std::mutex file_mutex_;
  /// Ln read-only data files.
  std::vector<std::vector<std::shared_ptr<FileInfo>>> files_;

  /// Approximate value of the space occupied by data files.
  std::atomic_int64_t space_used_{0};
};

} // namespace bitcask
