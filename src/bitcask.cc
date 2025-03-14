#include "bitcask/bitcask.h"

#include <algorithm>
#include <cstring>
#include <numeric>

#include "bitcask/errors.h"
#include "bitcask/format.h"
#include "util.h"

#ifndef XXH_INLINE_ALL
#define XXH_INLINE_ALL
#endif
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
namespace {

template <size_t N>
uint64_t Hash64(const std::span<const iovec, N>& parts) noexcept {
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

std::error_code LoadFromFile(int fd, void* buf, size_t len, size_t& off) noexcept {
  while (len) {
    int ret = ::pread(fd, buf, len, off);

    if (ret == -1) {
      return std::make_error_code(static_cast<std::errc>(errno));
    } else if (ret == 0) {
      return MakeErrorCode(BitcaskError::kUnexpectedEndOfFile);
    } else {
      buf = static_cast<std::byte*>(buf) + ret;
      len -= ret;
      off += ret;
    }
  }

  return {};
}

/**
 * Reads full content of an entry.
 *
 * @param fd
 * @param offset beginning of the entry.
 * @param check_crc check consistency of read data.
 *
 * @returns bytes read or an error code.
 */
std::pair<size_t, std::error_code> ReadEntryImpl(const int fd, const size_t offset, const bool check_crc,
    format::Entry& entry, std::string& key, std::string& value) {
  size_t current_offset = offset;
  uint64_t crc;
  // Load crc.
  if (auto ec = LoadFromFile(fd, &crc, sizeof(crc), current_offset)) {
    return {{}, ec};
  }
  // Load entry.
  if (auto ec = LoadFromFile(fd, &entry, sizeof(entry), current_offset)) {
    return {{}, ec};
  }
  // Validate entry.
  // TODO: max_value_size
  key.resize(entry.key_size);
  value.resize(entry.value_size);
  // Load value.
  if (auto ec = LoadFromFile(fd, value.data(), value.size(), current_offset)) {
    return {{}, ec};
  }
  // Load key.
  if (auto ec = LoadFromFile(fd, key.data(), key.size(), current_offset)) {
    return {{}, ec};
  }

  // Check crc.
  if (check_crc) {
    const std::array parts{
        iovec{.iov_base = &entry, .iov_len = sizeof(entry)},
        iovec{.iov_base = value.data(), .iov_len = value.size()},
        iovec{.iov_base = key.data(), .iov_len = key.size()},
    };

    if (Hash64(std::span(parts)) != crc) {
      return {{}, MakeErrorCode(BitcaskError::kInconsistent)};
    }
  }

  return {current_offset - offset, {}};
}

} // namespace

std::error_code Database::ActiveFile::FlushWithDelay(
    const std::chrono::nanoseconds delay, std::unique_lock<std::mutex> write_lock) {
  // Check the thread is ownign the lock.
  assert(write_lock.owns_lock());

  auto queue = wait_queue.lock();

  if (queue) {
    write_lock.unlock();
    // Wait for the result.
    return queue->result.get();
  } else {
    this->wait_queue = (queue = std::make_shared<WaitQueue>());
  }

  const auto deadline = std::chrono::steady_clock::now() + delay;
  // Wait until deadline.
  while (queue->cond.wait_until(write_lock, deadline) != std::cv_status::timeout) {
    if (!file) {
      break;
    }
  }

  std::error_code e;
  // Flush the data if the file is still writeable.
  if (file) {
    if (int ret = ::fsync(file->fd); ret != 0) {
      e = std::make_error_code(static_cast<std::errc>(errno));
    }
  }
  // Notify other waitees.
  queue->promise.set_value(e);
  // Reset the queue.
  this->wait_queue = {};

  return e;
}

bool Database::ActiveFile::MaybeFlushImmediately(const std::chrono::nanoseconds delay) {
  const auto now = std::chrono::steady_clock::now();
  const bool result = (now - last_write) > delay;

  last_write = now;

  return result;
}

std::error_code Database::FileInfo::Append(const std::span<const iovec>& parts, const bool sync) noexcept {
  const size_t length = std::accumulate(
      parts.begin(), parts.end(), 0ul, [](const auto acc, const auto& p) { return acc + p.iov_len; });

  const ssize_t ret = ::writev(fd, parts.data(), parts.size());
  // Write errors.
  if (ret == -1) {
    return std::make_error_code(static_cast<std::errc>(errno));
  }
  if (ret != length) {
    return std::make_error_code(std::errc::io_error);
  }
  // Force flush of written data.
  if (sync) {
    ::fsync(fd);
  }
  // Update total size of the file.
  size += length;

  return {};
}

bool Database::FileInfo::CloseFile(bool sync) {
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

std::error_code Database::FileInfo::EnsureReadable() {
  // Acquire exclusive access to a file descriptor to avoid opening the file
  // multiple times.
  std::lock_guard fd_lock(fd_mutex);

  if (fd == -1) {
    fd = ::open(path.c_str(), O_RDONLY);
    // Cannot open file for reading.
    if (fd == -1) {
      return std::make_error_code(static_cast<std::errc>(errno));
    }
  }

  return {};
}

Database::Database(const Options& options, const std::filesystem::path& path)
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

Database::~Database() {
  // Close writable files.
  for (const auto& item : active_files_) {
    if (item.file) {
      item.file->CloseFile(options_.flush_mode != FlushMode::kNone);
    }
  }
  // Close read-only files.
  for (const auto& parts : files_) {
    std::for_each(parts.begin(), parts.end(), [](const auto& f) { f->CloseFile(); });
  }
}

std::error_code Database::Open(
    const Options& options, const std::filesystem::path& path, std::unique_ptr<Database>& db) {
  db = std::unique_ptr<Database>(new Database(options, path));
  // Scan database directory.
  return db->Initialize();
}

std::error_code Database::Delete(const WriteOptions& options, const std::string_view key) {
  std::shared_lock op_lock(operation_mutex_);

  if (options_.read_only) {
    return MakeErrorCode(BitcaskError::kReadOnly);
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
  //
  const auto flush_mode = (options.sync && (options_.flush_mode != FlushMode::kDelay))
                              ? FlushMode::kImmediately
                              : options_.flush_mode;
  // Write the tombstone.
  auto [_, ec] = WriteEntry(key, {}, timestamp.value(), true, flush_mode);
  if (ec) {
    return ec;
  }

  std::unique_lock key_lock(key_mutex_);
  // Update key-set
  if (updated_keys_) {
    const bool present_in_main = keys_.contains(key);
    // During the merging process only the updated_keys_ can be modified.
    if (auto ki = updated_keys_->find(key); ki != updated_keys_->end()) {
      if (ki->second.file) {
        ki->second.file->obsolete.fetch_add(1);
      }
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

void Database::Enumerate(const std::function<void(const std::string_view)>& cb) const {
  std::shared_lock op_lock(operation_mutex_);
  std::shared_lock key_lock(key_mutex_);

  for (const auto& [key, _] : keys_) {
    cb(key);
  }
}

std::error_code Database::Get(
    const ReadOptions& options, const std::string_view key, std::string* value) const {
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
      return {};
    }
  }

  return MakeErrorCode(BitcaskError::kNotFound);
}

std::error_code Database::Put(
    const WriteOptions& options, const std::string_view key, const std::string_view value) {
  std::shared_lock op_lock(operation_mutex_);

  if (key.size() > std::numeric_limits<decltype(format::Entry::key_size)>::max()) {
    return MakeErrorCode(BitcaskError::kInvalidArgument);
  }
  if (value.size() > std::numeric_limits<decltype(format::Entry::value_size)>::max()) {
    return MakeErrorCode(BitcaskError::kInvalidArgument);
  }
  if (options_.read_only) {
    return MakeErrorCode(BitcaskError::kReadOnly);
  }
  // Acquire exclusive access to the key.
  LockKey(key, nullptr);

  const uint64_t timestamp = ++clock_;

  [[maybe_unused]] Defer d([this, key] { UnlockKey(key); });
  //
  const auto flush_mode = (options.sync && (options_.flush_mode != FlushMode::kDelay))
                              ? FlushMode::kImmediately
                              : options_.flush_mode;
  // Write the value with the specific timestamp.
  auto [record, ec] = WriteEntry(key, value, timestamp, false, flush_mode);
  if (ec) {
    return ec;
  }

  std::unique_lock key_lock(key_mutex_);
  // Update key-set
  if (updated_keys_) {
    // During the merging process only the updated_keys_ can be modified.
    if (auto ki = updated_keys_->find(key); ki == updated_keys_->end()) {
      updated_keys_->emplace(key, record);
    } else {
      if (ki->second.file) {
        ki->second.file->obsolete.fetch_add(1);
      }
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

uint64_t Database::ApproximateSpaceUsed() const noexcept {
  return std::max(int64_t(0), space_used_.load(std::memory_order_relaxed));
}

void Database::CloseFiles() {
  std::lock_guard file_lock(file_mutex_);

  for (const auto& parts : files_) {
    std::for_each(parts.begin(), parts.end(), [](const auto& f) { f->CloseFile(); });
  }
}

std::error_code Database::Pack(bool force) {
  for (size_t i = 0; i != compaction_slots_count_; ++i) {
    std::vector<std::shared_ptr<FileInfo>> files;
    CompactionMode mode;

    {
      std::unique_lock op_lock(operation_mutex_);

      // Check whether the compaction process is already in progress.
      if (updated_keys_) {
        return MakeErrorCode(BitcaskError::kInProgress);
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

    auto ec = PackFiles(files, mode, i);

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

    if (ec) {
      std::lock_guard file_lock(file_mutex_);

      files_[i].insert(
          files_[i].end(), std::make_move_iterator(files.begin()), std::make_move_iterator(files.end()));

      return ec;
    }

    // Cleanup processed files.
    for (const auto& file : files) {
      assert(file.use_count() == 1);

      file->CloseFile();
      // Adjust counter of used space.
      space_used_.fetch_sub(file->size, std::memory_order_relaxed);
      // Remove processed file from the storage device.
      std::filesystem::remove(file->path);
    }
  }

  return {};
}

std::error_code Database::Rotate() {
  std::shared_lock op_lock(operation_mutex_);
  std::vector<std::shared_ptr<FileInfo>> files;

  if (options_.read_only) {
    return MakeErrorCode(BitcaskError::kReadOnly);
  }

  for (auto& item : active_files_) {
    // Acquire exclusive access for writing to active file.
    std::lock_guard write_lock(item.write_mutex);
    //
    if (auto wait_queue = item.wait_queue.lock()) {
      wait_queue->cond.notify_all();
    }
    // Check if there is a file opened for writing.
    if (item.file) {
      files.push_back(std::move(item.file));
    }
  }

  // Close files for writing.
  for (const auto& f : files) {
    f->CloseFile(options_.flush_mode != FlushMode::kNone);
  }
  // Acquire exclusive access to the list of data files.
  std::lock_guard file_lock(file_mutex_);
  // Move data files into the read-only set.
  files_[0].insert(
      files_[0].end(), std::make_move_iterator(files.begin()), std::make_move_iterator(files.end()));

  return {};
}

std::error_code Database::Initialize() {
  std::vector<std::filesystem::path> cleanup;
  unordered_string_map<uint64_t> tombstones;

  const auto cb = [&](const Record& record, bool is_tombstone, std::string_view key) -> std::error_code {
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

  for (const auto& entry : std::filesystem::directory_iterator(base_path_)) {
    if (!entry.is_regular_file()) {
      continue;
    }
    if (entry.path().extension() != ".dat") {
      if (options_.clean_temporary_on_startup && entry.path().extension() == ".tmp") {
        cleanup.push_back(entry.path());
      }
      continue;
    }

    auto index = ParseLayoutIndex(entry.path().filename().string());
    if (!index) {
      continue;
    }

    auto file = std::make_shared<FileInfo>(entry.path(), entry.file_size(), index.value() == 0);
    // Open file for reading.
    if (auto ec = file->EnsureReadable()) {
      return ec;
    }
    [[maybe_unused]] Defer do_close([file]() { file->CloseFile(); });
    // Read keys from the file.
    if (auto ec = EnumerateKeys(file, cb)) {
      if (IsNotFound(ec)) {
        continue;
      }
      // A former active file may have a partially written record at the end in case of unexpected shutdown.
      // Ignore it.
      if (IsUnexpectedEndOfFile(ec) && file->may_have_uncommitted) {
        continue;
      }

      return ec;
    }

    // Adjust the counter of space used.
    space_used_.fetch_add(file->size, std::memory_order_relaxed);
    // Move data file into the read-only set.
    if (index.value() >= compaction_slots_count_) {
      files_[0].push_back(std::move(file));
    } else {
      files_[index.value()].push_back(std::move(file));
    }
  }

  // Cleanup temporaries.
  for (const auto& path : cleanup) {
    std::error_code ec;

    std::filesystem::remove(path, ec);
  }

  return {};
}

bool Database::IsLastCompactionLevel(const size_t i) const noexcept {
  return i >= compaction_levels_.back().first && i <= compaction_levels_.back().second;
};

std::error_code Database::PackFiles(
    const std::vector<std::shared_ptr<FileInfo>>& files, const CompactionMode mode, const int slot) {
  std::vector<std::vector<std::shared_ptr<FileInfo>>> output(8);
  // Mapping from source to target files.
  std::vector<std::tuple<unsigned, unsigned, Record, decltype(keys_)::iterator>> remap;
  std::vector<std::pair<decltype(keys_)::iterator, Record>> updates;

  [[maybe_unused]] Defer defer_cleanup([&] {
    for (const auto& files : output) {
      for (const auto& f : files) {
        if (!bool(f)) {
          continue;
        }
        // Adjust the counter of space used.
        space_used_.fetch_sub(f->size, std::memory_order_relaxed);
        // Remove temporary file.
        std::filesystem::remove(f->path);
      }
    }
  });

  const auto get_scatter_slot = [slot](const size_t i) { return (slot * 8 + 1) + i; };

  // 0. Build remapping.
  for (size_t i = 0, end = files.size(); i != end; ++i) {
    const auto& file = files[i];
    // Acquiring read lock to prevent closing the file handle during the read.
    std::shared_lock read_lock(file->read_mutex);

    // Ensure source file is opened.
    if (auto ec = file->EnsureReadable()) {
      return ec;
    }

    const auto remap_cb = [&](const Record& record, const bool is_tombstone,
                              const std::string_view key) -> std::error_code {
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

      if (mode == CompactionMode::kScatter) {
        remap.emplace_back(XXH64(key.data(), key.size(), slot + 1) % 8, i, record, ki);
      } else {
        remap.emplace_back(0, i, record, ki);
      }
      return {};
    };

    // Enumerate all records in the source file.
    if (auto ec = EnumerateKeys(file, remap_cb)) {
      // A former active file may have a partially written record at the end in case of unexpected
      // shutdown. Ignore it.
      if (IsUnexpectedEndOfFile(ec) && file->may_have_uncommitted) {
        continue;
      }
      return ec;
    }

    read_lock.unlock();
    // Close the file to avoid possible exhaustion of available file handles.
    file->CloseFile();
  }

  // Sort remap.
  std::sort(remap.begin(), remap.end(), [](const auto& a, const auto& b) {
    return std::make_tuple(std::get<0>(a), std::get<1>(a), std::get<2>(a).offset) <
           std::make_tuple(std::get<0>(b), std::get<1>(b), std::get<2>(b).offset);
  });

  FileInfo* current_file = {};
  std::unique_ptr<std::shared_lock<std::shared_mutex>> read_lock;

  for (const auto& [dst, _, record, ki] : remap) {
    if (current_file != record.file) {
      read_lock.reset();
      // Close the file to avoid possible exhaustion of available file handles.
      if (current_file) {
        current_file->CloseFile();
      }

      // Set current file.
      current_file = record.file;
      // Acquiring read lock to prevent closing the file handle during the read.
      read_lock = std::make_unique<std::shared_lock<std::shared_mutex>>(current_file->read_mutex);
      // Ensure source file is opened.
      if (auto ec = current_file->EnsureReadable()) {
        return ec;
      }
    }

    format::Entry e;
    std::string key;
    std::string value;

    auto [read, ec] = ReadEntryImpl(current_file->fd, record.offset, false, e, key, value);
    if (ec) {
      return ec;
    }

    const auto [rec, ec2] = WriteEntryToFile(key, value, record.timestamp, e.is_tombstone(), false,
        // Target file provider.
        [&](const uint64_t length) -> FileInfoStatus {
          // Ensure destination file is allocated.
          if (output[dst].empty() || IsCapacityExceeded(output[dst].back()->size, length)) {
            const auto index = (mode == CompactionMode::kGather) ? slot : get_scatter_slot(dst);

            auto [file, ec] = MakeWritableFile(
                std::to_string(index) + "-" + std::to_string(++clock_) + ".tmp", options_.write_index);
            if (ec) {
              assert(!bool(file));
              return {{}, ec};
            }

            output[dst].push_back(std::move(file));
          }

          return {output[dst].back(), {}};
        });

    if (ec2) {
      return ec2;
    }
    // Store updated record.
    if (ki != keys_.end()) {
      updates.emplace_back(ki, rec);
    }
  }

  read_lock.reset();
  // Close the file to avoid possible exhaustion of available file handles.
  if (current_file) {
    current_file->CloseFile();
  }

  const auto rename_temporary = [](const auto& file) -> std::error_code {
    std::error_code ec;

    const auto target = std::filesystem::path(file->path).replace_extension("dat");
    // Move file.
    std::filesystem::rename(file->path, target, ec);
    // Check error code.
    if (ec) {
      return ec;
    }
    // Update location of the file.
    file->path = std::move(target);

    return {};
  };

  // 2. Finalize output files.
  for (size_t i = 0, end = output.size(); i != end; ++i) {
    for (const auto& f : output[i]) {
      // Append index at the end of file.
      if (options_.write_index) {
        if (auto ec = WriteIndex(f)) {
          return ec;
        }
      }
      // Ensure that all data has been written to the storage device
      // before deleting the source files.
      f->CloseFile(true);
      // Rename temporary file.
      if (auto ec = rename_temporary(f)) {
        return ec;
      }
    }
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
    const auto index = (mode == CompactionMode::kGather) ? slot : get_scatter_slot(i);

    files_[index].insert(files_[index].end(), std::make_move_iterator(output[i].begin()),
        std::make_move_iterator(output[i].end()));
  }
  // 5. Cleanup.
  output.clear();

  return {};
}

std::optional<Database::Record> Database::GetKeyNoLock(const std::string_view key) const {
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

void Database::LockKey(const std::string_view key, std::shared_lock<std::shared_mutex>* lock) {
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

void Database::UnlockKey(const std::string_view key) {
  std::unique_lock lock_lock(lock_mutex_);

  if (key_locks_.erase(key) == 0) {
    std::terminate();
  }

  lock_cond_.notify_all();
}

void Database::WaitKeyUnlocked(
    const std::string_view key, std::shared_lock<std::shared_mutex>& lock) const {
  std::unique_lock lock_lock(lock_mutex_);

  // Wait the key will be unlocked by a concurent thread.
  while (key_locks_.contains(key)) {
    lock_cond_.wait(lock_lock);
  }

  lock.lock();
}

std::error_code Database::EnumerateKeys(const std::shared_ptr<FileInfo>& file,
    const std::function<std::error_code(const Record&, const bool, std::string_view)>& cb) const {
  FileSections sections;

  if (auto ec = LoadFileSections(file, &sections)) {
    return ec;
  }

  if (sections.index) {
    return EnumerateIndex(file, sections.index.value(), cb);
  } else {
    return EnumerateEntries(file, sections.entries.value(),
        [&](const Record& record, const bool is_tombstone, std::string_view key, std::string_view) {
          return cb(record, is_tombstone, key);
        });
  }
}

std::error_code Database::EnumerateIndex(const std::shared_ptr<FileInfo>& file,
    const FileSections::Range& range,
    const std::function<std::error_code(const Record&, const bool, std::string_view)>& cb) const {
  // Temporary buffer.
  std::vector<std::byte> buf((64ul << 10) + 4096u);
  // Current offset in the temporary buffer.
  std::byte* buf_ptr = buf.data();
  // Size of the data in the buffer.
  size_t buf_size = 0;
  uint64_t crc;
  format::Index index;

  for (size_t offset = range.first, end = range.second; offset < end;) {
    const auto size = std::min<size_t>((buf.size() - (buf_ptr - buf.data())), end - offset);
    // Load data from file.
    if (auto ec = LoadFromFile(file->fd, buf_ptr, size, offset)) {
      return ec;
    }
    // Adjust size of the data in the buffer.
    buf_size = (buf_ptr - buf.data()) + size;
    // Reset buffer pointer.
    buf_ptr = buf.data();

    while (buf_ptr < buf.data() + buf_size) {
      // Check whether the header within the buffer.
      if (auto left = buf_size - (buf_ptr - buf.data()); left < sizeof(crc) + sizeof(index)) {
        std::memmove(buf.data(), buf_ptr, left);

        buf_ptr = buf.data() + left;
        // Load more data.
        break;
      }

      // Load crc.
      std::memcpy(&crc, buf_ptr, sizeof(crc));
      // Load entry.
      std::memcpy(&index, buf_ptr + sizeof(crc), sizeof(index));
      // Advance the pointer.
      buf_ptr += sizeof(crc) + sizeof(index);
      // Check crc.
      const std::array parts{
          iovec{.iov_base = &index, .iov_len = sizeof(index)},
          iovec{.iov_base = buf_ptr, .iov_len = index.key_size},
      };
      if (Hash64(std::span(parts)) != crc) {
        return MakeErrorCode(BitcaskError::kInconsistent);
      }
      // Check whether the key within the buffer.
      if (buf_ptr + index.key_size > buf.data() + buf_size) {
        return MakeErrorCode(BitcaskError::kUnexpectedEndOfFile);
      }

      // Setup the key.
      const std::string_view key((const char*)buf_ptr, index.key_size);
      // Setup the record.
      const Record record{
          .file = file.get(),
          .timestamp = index.timestamp,
          .offset = uint32_t(index.entry_pos),
          .size = index.value_size,
      };

      if (auto ec = cb(record, index.flags & format::kEntryFlagTombstone, key)) {
        return ec;
      }

      // Advance the pointer.
      buf_ptr += key.size();
    }
  }

  // Check the buffer is fully read.
  assert(buf_ptr == buf.data() + buf_size);

  return {};
}

std::error_code Database::EnumerateEntries(const std::shared_ptr<FileInfo>& file,
    const FileSections::Range& range,
    const std::function<std::error_code(const Record&, const bool, std::string_view, std::string_view)>& cb)
    const {
  const auto fd = file->fd;
  std::string key;
  std::string value;

  for (size_t offset = range.first, end = range.second; offset < end;) {
    format::Entry e;

    auto [read, ec] = ReadEntryImpl(fd, offset, false, e, key, value);
    if (ec) {
      return ec;
    }

    const Record record{
        .file = file.get(),
        .timestamp = e.timestamp,
        .offset = uint32_t(offset),
        .size = uint32_t(value.size()),
    };

    if (auto s = cb(record, (e.flags & format::kEntryFlagTombstone), key, value)) {
      return s;
    }

    offset += read;
  }

  return {};
}

std::error_code Database::EnumerateEntriesNoLock(const std::shared_ptr<FileInfo>& file,
    const std::function<std::error_code(const Record&, const bool, std::string_view, std::string_view)>& cb)
    const {
  FileSections sections;

  if (auto ec = LoadFileSections(file, &sections)) {
    return ec;
  }

  return EnumerateEntries(file, sections.entries.value(), cb);
}

bool Database::IsCapacityExceeded(const uint64_t current_size, const uint64_t length) const noexcept {
  static constinit auto kMaxEntryOffset = std::numeric_limits<decltype(Record::offset)>::max();

  return
      // Ensure that the offset of the value does not overflow.
      (current_size) > kMaxEntryOffset ||
      // Ensure that the limit of the file size will not be exceeded.
      (current_size + length > options_.max_file_size);
}

Database::FileInfoStatus Database::MakeWritableFile(const std::string& name, bool with_footer) const {
  static constexpr std::filesystem::perms kDefaultPremissions =
      std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
      std::filesystem::perms::group_read | std::filesystem::perms::others_read;

  auto path = base_path_ / name;
  auto fd = ::open(path.c_str(), O_APPEND | O_RDWR | O_CREAT | O_EXCL, kDefaultPremissions);
  // Cannot open file for writing.
  if (fd == -1) {
    return {{}, std::make_error_code(static_cast<std::errc>(errno))};
  } else {
    const format::Header header{.magic = {'B', 'C', 'S', 'K', 'V', '1'},
        .flags = with_footer ? format::kFileFlagWithFooter : format::kFileFlagNone};

    if (::write(fd, &header, sizeof(header)) == -1) {
      int err = errno;
      ::close(fd);
      return {{}, std::make_error_code(static_cast<std::errc>(err))};
    }
  }
  auto file = std::make_shared<FileInfo>(std::move(path), sizeof(format::Header), name.starts_with("0-"));
  file->fd = fd;
  return {file, {}};
}

std::error_code Database::ReadValue(
    const ReadOptions& options, const Record& record, std::string& value) const {
  // Acquiring read lock to prevent closing the file handle during the read.
  std::shared_lock read_lock(record.file->read_mutex);

  // Ensure the reading range is valid.
  if (const auto& range = options.range) {
    if (range->size > record.size || range->offset > record.size - range->size) {
      return MakeErrorCode(BitcaskError::kInvalidRange);
    }
    // Return an empty value if the size of the range is zero.
    if (range->size == 0) [[unlikely]] {
      value.clear();
      return {};
    }
  }
  // Ensure file is opened.
  if (auto ec = record.file->EnsureReadable()) {
    return ec;
  }

  if (options.verify_checksums) {
    size_t offset = record.offset;
    format::Entry e;
    std::string key;

    if (auto ec = ReadEntryImpl(record.file->fd, offset, true, e, key, value).second) {
      return ec;
    }
    if (const auto& range = options.range) {
      value.assign(value.data() + range->offset, range->size);
    }
    return {};
  } else {
    size_t offset = record.offset + (sizeof(uint64_t) + sizeof(format::Entry));
    // Allocate memory for the value.
    if (const auto& range = options.range) {
      value.resize(range->size);
      // Adjust reading offset.
      offset += range->offset;
    } else {
      value.resize(record.size);
    }
    // Load value.
    return LoadFromFile(record.file->fd, value.data(), value.size(), offset);
  }
}

std::pair<Database::Record, std::error_code> Database::WriteEntry(const std::string_view key,
    const std::string_view value, const uint64_t timestamp, const bool is_tombstone, FlushMode flush_mode) {
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
        active_file.file->CloseFile(flush_mode != FlushMode::kNone);
        if (auto wait_queue = active_file.wait_queue.lock()) {
          wait_queue->cond.notify_all();
        }

        // Acquire exclusive access to list of data files.
        std::lock_guard file_lock(file_mutex_);
        // Move data file into the read-only set.
        files_[0].push_back(std::move(active_file.file));
      }
    }

    // Create new active file if none exists.
    if (!bool(active_file.file)) {
      auto [file, ec] = MakeWritableFile("0-" + std::to_string(++clock_) + ".dat", false);
      if (ec) {
        assert(!bool(file));
        return {{}, ec};
      } else {
        active_file.file = std::move(file);
      }
    }

    return {active_file.file, {}};
  };

  if (flush_mode == FlushMode::kDelay && active_file.MaybeFlushImmediately(options_.flush_delay)) {
    flush_mode = FlushMode::kImmediately;
  }

  auto [record, ec] = WriteEntryToFile(
      key, value, timestamp, is_tombstone, flush_mode == FlushMode::kImmediately, file_provider);
  // Return any error immediately.
  if (ec || flush_mode != FlushMode::kDelay) {
    return {record, ec};
  }

  return {record, active_file.FlushWithDelay(options_.flush_delay, std::move(write_lock))};
}

std::error_code Database::WriteIndex(const std::shared_ptr<FileInfo>& file) {
  const auto cb = [&](const Record& rec, const bool is_tombstone, const std::string_view key,
                      const std::string_view) {
    uint64_t crc;
    const format::Index index{
        .timestamp = rec.timestamp,
        .entry_pos = rec.offset,
        .value_size = rec.size,
        .key_size = uint16_t(key.size()),
        .flags = uint8_t(is_tombstone ? format::kEntryFlagTombstone : 0),
    };

    const std::array parts = {
        iovec{.iov_base = &crc, .iov_len = sizeof(crc)},
        iovec{.iov_base = (void*)&index, .iov_len = sizeof(index)},
        iovec{.iov_base = (void*)key.data(), .iov_len = key.size()},
    };

    crc = Hash64(std::span(parts).subspan<1>());

    return file->Append(parts, false);
  };

  format::Footer footer{.entries = sizeof(format::Header), .index = file->size};
  // Write index entries.
  if (auto ec = EnumerateEntries(file, std::make_pair(footer.entries, footer.index), cb)) {
    return ec;
  }
  // Write footer.
  return file->Append(std::array{iovec{.iov_base = &footer, .iov_len = sizeof(footer)}}, false);
}

std::error_code Database::LoadFileSections(const std::shared_ptr<FileInfo>& file, FileSections* sections) {
  format::Header header;
  size_t offset = 0;
  // Load header.
  if (auto ec = LoadFromFile(file->fd, &header, sizeof(header), offset)) {
    return ec;
  } else if (std::memcmp(header.magic, format::kFileMagicV1, format::kFileMagicSize) != 0) {
    return MakeErrorCode(BitcaskError::kNotFound);
  }
  // Load footer.
  if (header.flags & format::kFileFlagWithFooter) {
    format::Footer footer;
    size_t footer_offset = file->size - sizeof(footer);
    if (auto ec = LoadFromFile(file->fd, &footer, sizeof(footer), footer_offset)) {
      return ec;
    }
    if (footer.entries > footer.index) {
      return MakeErrorCode(BitcaskError::kInconsistent);
    }

    sections->header = std::pair{0, sizeof(header)};
    sections->entries = std::pair{footer.entries, footer.index};
    sections->index = std::pair{footer.index, file->size - sizeof(footer)};
    sections->footer = std::pair{file->size - sizeof(footer), file->size};
  } else {
    sections->header = std::pair{0, sizeof(header)};
    sections->entries = std::pair{sizeof(header), file->size};
  }

  return {};
}

std::optional<int> Database::ParseLayoutIndex(std::string_view name) {
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

std::pair<Database::Record, std::error_code> Database::WriteEntryToFile(const std::string_view key,
    const std::string_view value, const uint64_t timestamp, const bool is_tombstone, const bool sync,
    const std::function<FileInfoStatus(uint64_t)>& cb) {
  assert(!is_tombstone || value.empty());

  uint64_t crc;
  // Fill entry.
  const format::Entry entry{
      .timestamp = timestamp,
      .value_size = uint32_t(value.size()),
      .key_size = uint16_t(key.size()),
      .flags = uint8_t(is_tombstone ? format::kEntryFlagTombstone : 0x00),
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

  const auto [file, ec] = cb(length);
  if (ec) {
    return {{}, ec};
  }
  // Offset at which new entry will be written.
  const uint64_t offset = file->size;
  // Write data to the file.
  if (auto ec = file->Append(parts, sync)) {
    return {{}, ec};
  } else {
    space_used_.fetch_add(length, std::memory_order_relaxed);
  }

  // Count entries.
  if (is_tombstone) {
    file->tombstones.fetch_add(1, std::memory_order_relaxed);
  } else {
    file->records.fetch_add(1, std::memory_order_relaxed);
  }

  const Record record{
      .file = file.get(),
      .timestamp = timestamp,
      .offset = uint32_t(offset),
      .size = uint32_t(value.size()),
  };

  return {record, {}};
}

} // namespace bitcask
