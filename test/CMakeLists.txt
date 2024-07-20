add_executable(bitcask_test
  "main.cpp"
  "tests.cpp"
)

target_link_libraries(bitcask_test PRIVATE
  bitcask
)

add_test(bitcask_test bitcask_test)

