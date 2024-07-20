#pragma once

#include <filesystem>
#include <string>
#include <system_error>

#include <stdlib.h>
#include <unistd.h>

class TemporaryDirectory {
public:
  TemporaryDirectory() {
    std::string path = std::filesystem::temp_directory_path() / "XXXXXX";

    if (mkdtemp(path.data())) {
      path_ = std::move(path);
    } else {
      throw std::system_error(errno, std::system_category());
    }
  }

  ~TemporaryDirectory() {
    if (path_.size()) {
      std::filesystem::remove_all(path_);
    }
  }

  const std::string& GetPath() const noexcept {
    return path_;
  }

private:
  std::string path_;
};
