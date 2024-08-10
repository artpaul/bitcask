#include "bitcask/errors.h"

namespace bitcask {
namespace {

class BitcaskErrorCategory : public std::error_category {
 public:
  const char* name() const noexcept override { return "bitcask"; }

  std::string message(int ev) const override {
    switch (static_cast<BitcaskError>(ev)) {
      case BitcaskError::kNotFound:
        return "Not found";
      case BitcaskError::kInconsistent:
        return "Inconsistent";
      case BitcaskError::kInProgress:
        return "In progress";
      case BitcaskError::kInvalidArgument:
        return "Invalid argument";
      case BitcaskError::kReadOnly:
        return "Readn only";
      case BitcaskError::kUnexpectedEndOfFile:
        return "Unexpected end of file";
    }
    return "";
  }
};

static const BitcaskErrorCategory kErrorCategory{};

} // namespace

bool IsNotFound(const std::error_code ec) noexcept {
  return ec == std::error_code(static_cast<int>(BitcaskError::kNotFound), kErrorCategory);
}

bool IsInProgress(const std::error_code ec) noexcept {
  return ec == std::error_code(static_cast<int>(BitcaskError::kInProgress), kErrorCategory);
}

bool IsInvalidArgument(const std::error_code ec) noexcept {
  return ec == std::error_code(static_cast<int>(BitcaskError::kInvalidArgument), kErrorCategory);
}

bool IsInconsistent(const std::error_code ec) noexcept {
  return ec == std::error_code(static_cast<int>(BitcaskError::kInconsistent), kErrorCategory);
}

bool IsReadOnly(const std::error_code ec) noexcept {
  return ec == std::error_code(static_cast<int>(BitcaskError::kReadOnly), kErrorCategory);
}

bool IsUnexpectedEndOfFile(const std::error_code ec) noexcept {
  return ec == std::error_code(static_cast<int>(BitcaskError::kUnexpectedEndOfFile), kErrorCategory);
}

const std::error_category& BitcaskCategory() noexcept { return kErrorCategory; }

std::error_code MakeErrorCode(BitcaskError e) noexcept { return {static_cast<int>(e), kErrorCategory}; }

} // namespace bitcask
