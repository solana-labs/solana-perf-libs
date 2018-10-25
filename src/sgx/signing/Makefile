SGX_SDK ?= /opt/intel/sgxsdk
SIGN_ENCLAVE ?= 1
PRIV_KEY ?= ../keys/private_key.pem
PUB_KEY ?= ../keys/public_key.pem

SGX_COMMON_CFLAGS := -m64 -O2
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

Trusted_C_Flags := -Wno-implicit-function-declaration -std=c11 $(SGX_COMMON_CFLAGS) -nostdinc  -fpie -fstack-protector \
	-IInclude -I. -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx -fno-builtin-printf \
	-I. -fvisibility=hidden

Untrusted_C_Flags := -fPIC -O0 -g -Wno-attributes -I$(SGX_SDK)/include -I.
Test_C_Flags := $(Untrusted_C_Flags)

Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -lsgx_tcrypto -lsgx_tservice -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=./signing.lds

Common_C_Files := $(filter-out $(wildcard *_u*.c), $(wildcard *.c))
Common_C_Files := $(filter-out $(wildcard *_t*.c), $(Common_C_Files))
Common_C_Objects := $(Common_C_Files:.c=.o)

Trusted_C_Files := $(filter $(wildcard *_trusted.c), $(wildcard *.c))
Trusted_C_Files += signing_t.c
Trusted_C_Objects := $(Trusted_C_Files:.c=.o)

Untrusted_C_Files := $(filter $(wildcard *_untrusted.c), $(wildcard *.c))
Untrusted_C_Files += signing_u.c
Untrusted_C_Objects := $(Untrusted_C_Files:.c=.o)

.PHONY: all run

ifneq ($(SIGN_ENCLAVE), 0)
all: signing_u.c signing_t.c signing.signed.so libsigning.so
else
all: signing_u.c signing_t.c signing.so libsigning.so
	@echo "Build enclave signing.so success!"
	@echo
	@echo "**********************************************************************************************"
	@echo "PLEASE NOTE: In this mode, please sign the enclave first using Two Step Sign mechanism, before"
	@echo "you run the app to launch and access the enclave."
	@echo "**********************************************************************************************"
	@echo
endif

run: all

signing_t.c: $(SGX_EDGER8R) signing.edl
	@$(SGX_EDGER8R) --trusted signing.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

signing_u.c: $(SGX_EDGER8R) signing.edl
	@$(SGX_EDGER8R) --untrusted signing.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(Common_C_Objects): %.o: %.c
	$(CC) $(Trusted_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(Trusted_C_Objects): %.o: %.c
	$(CC) $(Trusted_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(Untrusted_C_Objects): %.o: %.c
	$(CC) $(Untrusted_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

signing.so: signing_t.o $(Trusted_C_Objects) $(Common_C_Objects)
	$(CC) $^ -o $@ $(Link_Flags)
	@echo "LINK =>  $@"

signing.signed.so: signing.so
	$(SGX_ENCLAVE_SIGNER) gendata -enclave $< -config signing.config.xml -out /tmp/enclave_hash.hex
	openssl dgst -sha256 -out /tmp/signature.hex -sign $(PRIV_KEY) -keyform PEM /tmp/enclave_hash.hex
	$(SGX_ENCLAVE_SIGNER) catsig -enclave $< -config signing.config.xml -out $@ -key $(PUB_KEY) -sig /tmp/signature.hex -unsigned /tmp/enclave_hash.hex
	@echo "SIGN =>  $@"

libsigning.so: signing_u.o signing_untrusted.o $(Untrusted_C_Objects) $(Common_C_Objects)
	$(CC) $^ -o $@ -shared -L$(SGX_LIBRARY_PATH) -lsgx_uae_service -lsgx_ukey_exchange -lsgx_urts
	@echo "LINK =>  $@"


clean:
	@rm -f signing_t.* signing_u.* $(Common_C_Objects) $(Trusted_C_Objects) $(Untrusted_C_Objects) signing.signed.so signing.so libsigning.so
