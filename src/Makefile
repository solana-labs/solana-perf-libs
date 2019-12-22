#
#  Makefile to build libcuda-crypt.so
#   From sources in /cuda-crypt and /ed25519-verify
#
#   nvcc inserts conflicting driver symbols into a static lib (.so)
#   so more than one .so cannot be linked into a single program.
#   Shared objects with device kernels also did not seem to work--
#   it can build, but the kernel launch is not successful. (with cuda 9.2)
#   Hence, build ed25519 ecdsa verify and chacha encryption device
#   code into a single binary.

V=debug
include gpu-common.mk

CHACHA_TEST_BIN=cuda_chacha_test
ECC_TEST_BIN=cuda_ed25519_verify
LIB=cuda-crypt

CL_ECC_TEST_BIN=cl_ed25519_verify
CL_LIB=cl-crypt

CHACHA_IF_DIR:=crypt-if

CL_HEADER_DIR:=opencl-platform

CUDA_HEADER_DIR:=cuda-headers
CUDA_SHA256_DIR:=cuda-sha256

CUDA_DIR ?= /usr/local/cuda

CXX ?= g++

CFLAGS_COMMON:=-DENDIAN_NEUTRAL -DLTC_NO_ASM -I$(CHACHA_IF_DIR)
CFLAGS+=$(CFLAGS_COMMON) -I$(CUDA_HEADER_DIR) -I$(CUDA_SHA256_DIR)

#use -DUSE_RDTSC for Windows compilation
CL_CFLAGS_common:=-fPIC -std=c++11 $(CFLAGS_COMMON) -DOPENCL_VARIANT \
		  -I$(CL_HEADER_DIR) -Icommon/ \
		  -I$(CUDA_DIR)/targets/x86_64-linux/include $(HOST_CFLAGS)
CL_CFLAGS_release:=$(CL_CFLAGS_common) -O3
CL_CFLAGS_debug:=$(CL_CFLAGS_common) -O0 -g
CL_CFLAGS:=$(CL_CFLAGS_$V)

all: $(V)/$(CHACHA_TEST_BIN) \
     $(V)/$(ECC_TEST_BIN) \
     $(V)/$(CL_ECC_TEST_BIN) \
     $(V)/lib$(LIB).so \
     $(V)/lib$(CL_LIB).so

ECC_DIR:=cuda-ecc-ed25519

KEYPAIR_SRCS:=$(addprefix $(ECC_DIR)/,keypair.cu ed25519.h ge.h)
$V/keypair.o: $(KEYPAIR_SRCS)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

SEED_SRCS:=$(addprefix $(ECC_DIR)/,seed.cu ed25519.h)
$V/seed.o: $(SEED_SRCS)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

SIGN_SRCS:=$(addprefix $(ECC_DIR)/,sign.cu sha512.h ge.h sc.h fe.cu ../common/gpu_common.h ed25519.h)
$V/sign.o: $(SIGN_SRCS)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

VERIFY_SRCS:=$(addprefix $(ECC_DIR)/,verify.cu sha512.cu ge.cu sc.cu fe.cu keypair.cu common.cu ed25519.h)
$V/verify.o: $(VERIFY_SRCS)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

$V/gpu_ctx.o: $(addprefix $(ECC_DIR)/,gpu_ctx.cu gpu_ctx.h)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

CL_ECC_DIR:=opencl-ecc-ed25519
CL_CRYPT_DIR:=opencl-crypt
CL_POH_VERIFY_DIR:=opencl-poh-verify

CL_POH_VERIFY_SRCS:=$(CL_POH_VERIFY_DIR)/cl_poh_verify.cpp
$V/cl_poh_verify.o: $(CL_POH_VERIFY_SRCS)
	@mkdir -p $(@D)
	$(CXX) $(CL_CFLAGS) -I$(ECC_DIR) -c $< -o $@

CL_CHACHA_SRCS:=$(CL_CRYPT_DIR)/cl_chacha.cpp
$V/cl_chacha.o: $(CL_CHACHA_SRCS)
	@mkdir -p $(@D)
	$(CXX) $(CL_CFLAGS) -I$(ECC_DIR) -c $< -o $@

CL_SIGN_SRCS:=$(CL_ECC_DIR)/sign.cpp $(ECC_DIR)/fe.cu $(ECC_DIR)/ed25519.h
$V/cl_sign.o: $(CL_SIGN_SRCS)
	@mkdir -p $(@D)
	$(CXX) $(CL_CFLAGS) -I$(ECC_DIR) -c $< -o $@

CL_VERIFY_SRCS:=$(CL_ECC_DIR)/verify.cpp $(ECC_DIR)/seed.cu $(ECC_DIR)/ed25519.h
$V/cl_verify.o: $(CL_VERIFY_SRCS)
	@mkdir -p $(@D)
	$(CXX) $(CL_CFLAGS) -I$(ECC_DIR) -c $< -o $@
	
$V/cl_gpu_ctx.o: $(addprefix $(CL_ECC_DIR)/,gpu_ctx.cpp gpu_ctx.h)
	@mkdir -p $(@D)
	$(CXX) $(CL_CFLAGS) -I$(ECC_DIR) -c $< -o $@
	
CHACHA_DIR:=cuda-crypt
CHACHA_SRCS:=$(addprefix $(CHACHA_DIR)/,chacha_cbc.cu common.cu) $(CHACHA_IF_DIR)/chacha.h

$V/chacha_cbc.o: $(CHACHA_SRCS)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

$V/cl_init_platform.o: opencl-platform/cl_init_platform.cpp
	@mkdir -p $(@D)
	$(CXX) $(CL_CFLAGS) -c $< -o $@

AES_SRCS:=$(addprefix $(CHACHA_DIR)/,aes_cbc.cu aes_core.cu modes_lcl.h common.cu)

$V/aes_cbc.o: $(AES_SRCS)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

POH_DIR:=cuda-poh-verify
POH_SRCS:=$(addprefix $(POH_DIR)/,poh_verify.cu)

$V/poh_verify.o: $(POH_SRCS)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

CL_CPU_GPU_OBJS=$(addprefix $V/,cl_init_platform.o cl_verify.o cl_gpu_ctx.o cl_sign.o cl_chacha.o cl_poh_verify.o)

$V/lib$(CL_LIB).so: $(CL_CPU_GPU_OBJS)
	$(CXX) -shared $^ -lOpenCL -o $@

$V/cl_ecc_main.o: $(CL_ECC_DIR)/main.cpp $(ECC_DIR)/ed25519.h
	@mkdir -p $(@D)
	$(CXX) $(CL_CFLAGS) -pthread -I$(ECC_DIR) -c $< -o $@

$V/$(CL_ECC_TEST_BIN): $V/cl_ecc_main.o $V/lib$(CL_LIB).so
	$(CXX) $(CL_CFLAGS) -L$(CUDA_DIR)/lib64 -L$V -pthread $< -l$(CL_LIB) -lOpenCL -o $@

CPU_GPU_OBJS=$(addprefix $V/,chacha_cbc.o aes_cbc.o verify.o poh_verify.o gpu_ctx.o sign.o seed.o keypair.o)

$V/crypt-dlink.o: $(CPU_GPU_OBJS)
	$(NVCC) -Xcompiler "-fPIC" $(CFLAGS) --device-link $^ --output-file $@

$V/lib$(LIB).so: $V/crypt-dlink.o $(CPU_GPU_OBJS)
	$(NVCC) -Xcompiler "-fPIC" --shared --output-file $@ $^

$V/$(CHACHA_TEST_BIN): $(CHACHA_DIR)/test.cu $V/lib$(LIB).so
	$(NVCC) $(CFLAGS) -L$V -l$(LIB) $< -o $@

$V/ecc_main.o: $(addprefix $(ECC_DIR)/,main.cu ed25519.h)
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

$V/$(ECC_TEST_BIN): $V/ecc_main.o $V/lib$(LIB).so
	$(NVCC) $(CFLAGS) -L$V -l$(LIB) $< -o $@

.PHONY:clean
clean:
	rm -rf $V

test: $V/$(ECC_TEST_BIN) $V/$(CHACHA_TEST_BIN)
	cd $(V) && ./$(CHACHA_TEST_BIN) 64 \
	cd $(V) && ./$(ECC_TEST_BIN) 1 1 1 1 1 1
	cd $(V) && ./$(ECC_TEST_BIN) 64 1 1 1 1 0
	cd $(V) && ./$(ECC_TEST_BIN) 100201 1 1 4 10 1
