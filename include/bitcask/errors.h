#pragma once

#include <system_error>

namespace bitcask {

enum class BitcaskError {
  /// Requested entity was not found.
  kNotFound = 1,
  /// Requested operation already in progress.
  kInProgress,
  /// Invalid argument.
  kInvalidArgument,
  /// Invalid range.
  kInvalidRange,
  /// Inconsistent state of the database.
  kInconsistent,
  /// Database was opened in read-only mode.
  kReadOnly,
  /// Part of the data is missing.
  kUnexpectedEndOfFile,
};

/// Returns true if the error code indicates a NotFound error.
bool IsNotFound(const std::error_code ec) noexcept;

/// Returns true if the error code indicates InProgress error.
bool IsInProgress(const std::error_code ec) noexcept;

/// Returns true if the error code indicates InvalidArgument error.
bool IsInvalidArgument(const std::error_code ec) noexcept;

/// Returns true if the error code indicates InvalidRange error.
bool IsInvalidRange(const std::error_code ec) noexcept;

/// Returns true if the error code indicates data inconsistency.
bool IsInconsistent(const std::error_code ec) noexcept;

/// Returns true if the error code indicates read-only mode.
bool IsReadOnly(const std::error_code ec) noexcept;

/// Returns true if the error code indicates unxpected end of a data file.
bool IsUnexpectedEndOfFile(const std::error_code ec) noexcept;

/// Returns a reference to the static error category object for bitcask errors.
const std::error_category& BitcaskCategory() noexcept;

/// Makes generic error code.
std::error_code MakeErrorCode(const BitcaskError) noexcept;

} // namespace bitcask

template <>
struct std::is_error_code_enum<bitcask::BitcaskError> : std::true_type {};
