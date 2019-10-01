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

CHACHA_TEST_BIN=cuda_chacha_test
ECC_TEST_BIN=cuda_ed25519_verify
LIB=cuda-crypt

CUDA_HEADER_DIR:=cuda-headers
CUDA_SHA256_DIR:=cuda-sha256

CFLAGS+=-DENDIAN_NEUTRAL -DLTC_NO_ASM -I$(CUDA_HEADER_DIR) -I$(CUDA_SHA256_DIR)
CL_CFLAGS=-DENDIAN_NEUTRAL -DLTC_NO_ASM -I$(CUDA_HEADER_DIR) -I$(CUDA_SHA256_DIR)

all: $V/$(CHACHA_TEST_BIN) $V/$(ECC_TEST_BIN) $(V)/lib$(LIB).so

ECC_DIR:=cuda-ecc-ed25519
VERIFY_SRCS:=$(addprefix $(ECC_DIR)/,verify.cu seed.cu sha512.cu ge.cu sc.cu fe.cu sign.cu keypair.cu common.cu ed25519.h)

$V/verify.o: $(VERIFY_SRCS)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

CHACHA_DIR:=cuda-crypt
CHACHA_SRCS:=$(addprefix $(CHACHA_DIR)/,chacha_cbc.cu chacha.h common.cu)

$V/chacha_cbc.o: $(CHACHA_SRCS)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@
	
# OpenCL platform code
# This is particular to OpenCL and is not required for CUDA
$V/cl_init_platform.o: opencl-platform/cl_init_platform.cpp
	@mkdir -p $(@D)
	g++ $(CL_CFLAGS) -c $< -o $@
	
# OpenCL transition compile rules 1
# TODO unify with CUDA ones
CL_CHACHA_DIR:=opencl-crypt
CL_CHACHA_SRCS:=$(addprefix $(CL_CHACHA_DIR)/,chacha_cbc.cpp chacha.h)

$V/cl_chacha_cbc.o: $(CL_CHACHA_SRCS)
	@mkdir -p $(@D)
	g++ $(CL_CFLAGS) -c $< -o $@

AES_SRCS:=$(addprefix $(CHACHA_DIR)/,aes_cbc.cu aes_core.cu modes_lcl.h common.cu)

$V/aes_cbc.o: $(AES_SRCS)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

# OpenCL transition compile rules 2
# TODO unify with CUDA ones
CL_AES_SRCS:=$(addprefix $(CL_CHACHA_DIR)/,aes_cbc.cpp modes_lcl.h)

$V/cl_aes_cbc.o: $(CL_AES_SRCS)
	@mkdir -p $(@D)
	g++ $(CL_CFLAGS) -c $< -o $@

POH_DIR:=cuda-poh-verify
POH_SRCS:=$(addprefix $(POH_DIR)/,poh_verify.cu)

$V/poh_verify.o: $(POH_SRCS)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

$V/crypt-dlink.o: $V/chacha_cbc.o $V/aes_cbc.o $V/verify.o $V/poh_verify.o
	$(NVCC) -Xcompiler "-fPIC" --gpu-architecture=compute_61 --device-link $^ --output-file $@

$V/lib$(LIB).a: $V/crypt-dlink.o $V/chacha_cbc.o $V/aes_cbc.o $V/verify.o $V/poh_verify.o
	$(NVCC) -Xcompiler "-fPIC" --lib --output-file $@ $^

$V/lib$(LIB).so: $V/crypt-dlink.o $V/chacha_cbc.o $V/aes_cbc.o $V/verify.o $V/poh_verify.o
	$(NVCC) -Xcompiler "-fPIC" --shared --output-file $@ $^

$V/$(CHACHA_TEST_BIN): $(CHACHA_DIR)/test.cu $V/lib$(LIB).a
	$(NVCC) $(CFLAGS) -L$V -l$(LIB) $< -o $@

$V/ecc_main.o: $(addprefix $(ECC_DIR)/,main.cu ed25519.h)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

$V/$(ECC_TEST_BIN): $V/ecc_main.o $V/lib$(LIB).a
	$(NVCC) $(CFLAGS) -L$V -l$(LIB) $< -o $@

.PHONY:clean
clean:
	rm -rf $V
