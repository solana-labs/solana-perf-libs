#
#  Makefile to build libcuda-crypt.a
#   From sources in /cuda-crypt and /ed25519-verify
#
#   nvcc inserts conflicting driver symbols into a static lib (.a)
#   so more than one .a cannot be linked into a single program.
#   Shared objects with device kernels also did not seem to work--
#   it can build, but the kernel launch is not successful. (with cuda 9.2)
#   Hence, build ed25519 ecdsa verify and chacha encryption device
#   code into a single binary.

V=debug
include gpu-common.mk

# OpenCL include/library
CL_HEADER_DIR:=/cygdrive/c/Program\ Files/NVIDIA\ GPU\ Computing\ Toolkit/CUDA/v10.0/include/
CL_LIBRARY_DIR:=/cygdrive/c/Program\ Files/NVIDIA\ GPU\ Computing\ Toolkit/CUDA/v10.0/lib/x64

CHACHA_TEST_BIN=cuda_chacha_test
ECC_TEST_BIN=cuda_ed25519_verify
LIB=cuda-crypt

CL_CHACHA_TEST_BIN=cl_chacha_test
CL_ECC_TEST_BIN=cl_ed25519_verify
CL_LIB=cl-crypt

CL_HEADER_DIR:=opencl-platform
CUDA_HEADER_DIR:=cuda-headers
CUDA_SHA256_DIR:=cuda-sha256

CFLAGS+=-DENDIAN_NEUTRAL -DLTC_NO_ASM -I$(CUDA_HEADER_DIR) -I$(CUDA_SHA256_DIR)
#use -DUSE_RDTSC for Windows compilation
CL_CFLAGS=-std=c++11 -DENDIAN_NEUTRAL -DLTC_NO_ASM -I$(CUDA_HEADER_DIR) -I$(CUDA_SHA256_DIR) -I$(CL_HEADER_DIR) -L$(CL_LIBRARY_DIR)

all: $V/$(CHACHA_TEST_BIN) $V/$(ECC_TEST_BIN) $(V)/lib$(LIB).so

ECC_DIR:=cuda-ecc-ed25519
VERIFY_SRCS:=$(addprefix $(ECC_DIR)/,verify.cu seed.cu sha512.cu ge.cu sc.cu fe.cu sign.cu keypair.cu common.cu ed25519.h)

$V/verify.o: $(VERIFY_SRCS)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

CL_ECC_DIR:=opencl-ecc-ed25519
CL_VERIFY_SRCS:=$(addprefix $(CL_ECC_DIR)/,verify.cpp seed.c sha512.c ge.c sc.c fe.c sign.c keypair.c common.c ed25519.h)

$V/cl_verify.o: $(CL_VERIFY_SRCS)
	@mkdir -p $(@D)
	g++ $(CL_CFLAGS) -c $< -o $@

CHACHA_DIR:=cuda-crypt
CHACHA_SRCS:=$(addprefix $(CHACHA_DIR)/,chacha_cbc.cu chacha.h common.cu)

$V/chacha_cbc.o: $(CHACHA_SRCS)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

$V/cl_init_platform.o: opencl-platform/cl_init_platform.cpp
	@mkdir -p $(@D)
	g++ $(CL_CFLAGS) -c $< -o $@

CL_CHACHA_DIR:=opencl-crypt
CL_CHACHA_SRCS:=$(addprefix $(CL_CHACHA_DIR)/,chacha_cbc.cpp chacha.h)

$V/cl_chacha_cbc.o: $(CL_CHACHA_SRCS)
	@mkdir -p $(@D)
	g++ $(CL_CFLAGS) -c $< -o $@

AES_SRCS:=$(addprefix $(CHACHA_DIR)/,aes_cbc.cu aes_core.cu modes_lcl.h common.cu)

$V/aes_cbc.o: $(AES_SRCS)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

CL_AES_SRCS:=$(addprefix $(CL_CHACHA_DIR)/,aes_cbc.cpp aes_core.cpp modes_lcl.h)

$V/cl_aes_cbc.o: $(CL_AES_SRCS)
	@mkdir -p $(@D)
	g++ $(CL_CFLAGS) -c $< -o $@

POH_DIR:=cuda-poh-verify
POH_SRCS:=$(addprefix $(POH_DIR)/,poh_verify.cu)

$V/poh_verify.o: $(POH_SRCS)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

CL_POH_DIR:=opencl-poh-verify
CL_POH_SRCS:=$(addprefix $(CL_POH_DIR)/,poh_verify.cpp)

$V/cl_poh_verify.o: $(CL_POH_SRCS)
	@mkdir -p $(@D)
	g++ $(CL_CFLAGS) -c $< -o $@

$V/cl_crypt-dlink.o: $V/cl_init_platform.o $V/cl_chacha_cbc.o $V/cl_aes_cbc.o $V/cl_verify.o $V/cl_poh_verify.o
	ar rvs $@ $^

$V/lib$(CL_LIB).a: $V/cl_crypt-dlink.o $V/cl_init_platform.o $V/cl_chacha_cbc.o $V/cl_aes_cbc.o $V/cl_verify.o $V/cl_poh_verify.o
	ar rcs $@ $^

$V/lib$(CL_LIB).so: $V/cl_crypt-dlink.o $V/cl_init_platform.o $V/cl_chacha_cbc.o $V/cl_aes_cbc.o $V/cl_verify.o $V/cl_poh_verify.o
	g++ -shared --shared $^ -o $@

$V/cl_ecc_main.o: $(addprefix $(CL_ECC_DIR)/,main.cpp ed25519.h)
	@mkdir -p $(@D)
	g++ $(CL_CFLAGS) -c $< -o $@

$V/$(CL_ECC_TEST_BIN): $V/cl_ecc_main.o $V/lib$(CL_LIB).a
	g++ $(CL_CFLAGS) -Wl,-v -L/usr/local/cuda-9.1/lib64 -L$V -lpthread $^ -lOpenCL -o $@

$V/crypt-dlink.o: $V/chacha_cbc.o $V/aes_cbc.o $V/verify.o $V/poh_verify.o
	$(NVCC) -Xcompiler "-fPIC" --gpu-architecture=compute_61 --device-link $^ --output-file $@

$V/lib$(LIB).a: $V/crypt-dlink.o $V/chacha_cbc.o $V/aes_cbc.o $V/verify.o $V/poh_verify.o
	$(NVCC) -Xcompiler "-fPIC" --lib --output-file $@ $^

$V/lib$(LIB).so: $V/crypt-dlink.o $V/chacha_cbc.o $V/aes_cbc.o $V/verify.o $V/poh_verify.o
	$(NVCC) -Xcompiler "-fPIC" --shared --output-file $@ $^

$V/$(CHACHA_TEST_BIN): $(CHACHA_DIR)/test.cu $V/lib$(LIB).a
	$(NVCC) $(CFLAGS) -L$V -l$(LIB) $< -o $@

$V/$(CL_CHACHA_TEST_BIN): $(CL_CHACHA_DIR)/test.cpp $V/lib$(CL_LIB).a
	g++ $(CL_CFLAGS) -Wl,-v -L/usr/local/cuda-9.1/lib64 -L$V -lpthread $^ -lOpenCL -o $@

$V/ecc_main.o: $(addprefix $(ECC_DIR)/,main.cu ed25519.h)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

$V/$(ECC_TEST_BIN): $V/ecc_main.o $V/lib$(LIB).a
	$(NVCC) $(CFLAGS) -L$V -l$(LIB) $< -o $@

.PHONY:clean
clean:
	rm -rf $V
