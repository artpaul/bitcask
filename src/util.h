#pragma once

#include <functional>

namespace bitcask {

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

} // namespace bitcask
