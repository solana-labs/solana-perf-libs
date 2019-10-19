cmake_minimum_required(VERSION 3.8 FATAL_ERROR)
project(cuda_crypt LANGUAGES CXX CUDA)

set(CUDA_ENCRYPT_DIR cuda-crypt)
set(CUDA_ECC_DIR cuda-ecc-ed25519)
set(CUDA_POH_VERIFY_DIR cuda-poh-verify)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include_directories(${CUDA_ECC_DIR} ${CUDA_ENCRYPT_DIR} cuda-sha256 cuda-headers common)

add_library(cuda-crypt SHARED
        ${CUDA_ECC_DIR}/verify.cu
        ${CUDA_ECC_DIR}/ed25519.h
        ${CUDA_ENCRYPT_DIR}/chacha_cbc.cu
        ${CUDA_POH_VERIFY_DIR}/poh_verify.cu
  )

target_compile_features(cuda-crypt PUBLIC cxx_std_11)
target_compile_options(cuda-crypt PRIVATE $<$<COMPILE_LANGUAGE:CUDA>: --generate-line-info>)

if(MSVC)
    set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --ptxas-options=-v -Xcompiler=\"/W4\"")
else()
    set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --ptxas-options=-v -Xcompiler=\"-Wall -Werror\"")
endif()

set_target_properties(cuda-crypt
                      PROPERTIES CUDA_SEPARABLE_COMPILATION ON)

set_target_properties(cuda-crypt
        PROPERTIES CUDA_SELECT_NVCC_ARCH_FLAGS 3.5+PTX 5.0 6.0 6.1 7.0)

add_definitions(-DED25519_BUILD_DLL)
add_definitions(-DENDIAN_NEUTRAL)
add_definitions(-DLTC_NO_ASM)

# cuda_ed25519_verify
add_executable(cuda_ed25519_verify ${CUDA_ECC_DIR}/main.cu)
set_property(TARGET cuda_ed25519_verify
             PROPERTY CUDA_SEPARABLE_COMPILATION ON)
target_link_libraries(cuda_ed25519_verify PUBLIC cuda-crypt)

# chacha_test
add_executable(chacha_test ${CUDA_ENCRYPT_DIR}/test_chacha.cu)
set_property(TARGET cuda_ed25519_verify
             PROPERTY CUDA_SEPARABLE_COMPILATION ON)
target_link_libraries(chacha_test PUBLIC cuda-crypt)

if(APPLE)
  # We need to add the path to the driver (libcuda.dylib) as an rpath,
  # so that the static cuda runtime can find it at runtime.
  set_property(TARGET cuda_ed25519_verify
               PROPERTY
               BUILD_RPATH ${CMAKE_CUDA_IMPLICIT_LINK_DIRECTORIES})
endif()
