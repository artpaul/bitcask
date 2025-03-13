#pragma once

#include <cstddef>
#include <cstdint>

namespace bitcask {
namespace format {

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

  constexpr bool is_tombstone() const noexcept { return (flags & kEntryFlagTombstone) != 0; }
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

} // namespace format
} // namespace bitcask
