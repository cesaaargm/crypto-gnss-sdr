cmake_minimum_required(VERSION 3.25)
project(crypto-gnss-sdr)

set(CMAKE_CXX_STANDARD 17)

add_executable(crypto-gnss-sdr main.cpp)

target_link_libraries(crypto-gnss-sdr PRIVATE ssl crypto cryptopp)



#[[
find_library(CRYPTOPP_LIBRARY NAMES libcryptopp.a)
include_directories(/usr/local/include/cryptopp)

if (CRYPTOPP_LIBRARY)
    target_link_libraries(SHA256 ${CRYPTOPP_LIBRARY})
else()
    message(FATAL_ERROR "Crypto++ library not found.")
endif()]]
