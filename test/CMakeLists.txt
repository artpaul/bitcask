add_executable(bitcask_test
  "main.cpp"
  "tests.cpp"
)

target_link_libraries(bitcask_test PRIVATE
  bitcask
)

if(UNIX)
  target_link_libraries(bitcask_test PUBLIC
    pthread
  )
endif()

add_test(bitcask_test bitcask_test)
