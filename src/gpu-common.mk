NVCC:=nvcc
GPU_PTX_ARCH:=compute_35
GPU_ARCHS?=sm_37,sm_50,sm_61,sm_70
HOST_CFLAGS:=-Wall -Werror -fPIC -Wno-strict-aliasing
GPU_CFLAGS:=--gpu-code=$(GPU_ARCHS),$(GPU_PTX_ARCH) --gpu-architecture=$(GPU_PTX_ARCH)

# enable for profiling
#GPU_CFLAGS+=-lineinfo

# enable to see kernel register stats
#GPU_CFLAGS+=--ptxas-options=-v

CFLAGS_release:=-Icommon $(GPU_CFLAGS) -O3 -Xcompiler "$(HOST_CFLAGS)"
CFLAGS_debug:=$(CFLAGS_release) -g
CFLAGS:=$(CFLAGS_$V)
