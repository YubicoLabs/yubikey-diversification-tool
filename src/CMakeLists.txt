#
# CMake preamble
#

cmake_minimum_required(VERSION 3.8 FATAL_ERROR)

#
# Target definition
#
project(yubikey-diversification-tool LANGUAGES CXX)
add_executable(yubikey-diversification-tool)

#
# Target build options
#
set(OPENSSL_USE_STATIC_LIBS TRUE)
set(OPENSSL_MSVC_STATIC_RT TRUE)
find_package(OpenSSL REQUIRED)

if(MSVC)
  add_compile_options(/W4 /WX)

  set(CompilerFlags
    CMAKE_CXX_FLAGS
    CMAKE_CXX_FLAGS_DEBUG
    CMAKE_CXX_FLAGS_RELEASE
    CMAKE_CXX_FLAGS_RELWITHDEBINFO
    CMAKE_C_FLAGS
    CMAKE_C_FLAGS_DEBUG
    CMAKE_C_FLAGS_RELEASE
    CMAKE_C_FLAGS_RELWITHDEBINFO
  )

  foreach(CompilerFlag ${CompilerFlags})
    string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
  endforeach()
else()
  add_compile_options(-Wall -Wextra -pedantic -Werror)
endif()

target_compile_definitions(yubikey-diversification-tool
  PRIVATE
  NDEBUG
)

#
# Include / Library dependencies
#
target_include_directories(yubikey-diversification-tool
  PRIVATE
  OpenSSL::Crypto
  ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(yubikey-diversification-tool
  PRIVATE
  OpenSSL::Crypto
)

#
# Source files
#
target_sources(yubikey-diversification-tool
  PRIVATE
  main.cpp
)

#
# Install
#
install(
  TARGETS
  yubikey-diversification-tool
  RUNTIME DESTINATION
  .
  COMPONENT "RUNTIME"
)
