CC=ispc
ISPC_FLAGS := -O2 --pic -I.
DEPS := sha256.h

ISPC_OBJ := ispcobj
ISPC_C_Objects := $(ISPC_OBJ)/poh-verify-sse2.o \
    		  $(ISPC_OBJ)/poh-verify-sse4.o \
		  $(ISPC_OBJ)/poh-verify-avx1.o \
		  $(ISPC_OBJ)/poh-verify-avx2.o \
		  $(ISPC_OBJ)/poh-verify-avx512skx.o

OUT ?= libs

.PHONY: all run
all: $(OUT)/libpoh-simd.a
run: all

$(ISPC_OBJ)/poh-verify-sse2.o: poh-verify.ipsc $(DEPS)
	@mkdir -p $(ISPC_OBJ)
	$(CC) --target=sse2-i32x4 -DNAME_SUFFIX=sse2 $(ISPC_FLAGS) $< -o $@

$(ISPC_OBJ)/poh-verify-sse4.o: poh-verify.ipsc $(DEPS)
	@mkdir -p $(ISPC_OBJ)
	$(CC) --target=sse4-i32x4 -DNAME_SUFFIX=sse4 $(ISPC_FLAGS) $< -o $@

$(ISPC_OBJ)/poh-verify-avx1.o: poh-verify.ipsc $(DEPS)
	@mkdir -p $(ISPC_OBJ)
	$(CC) --target=avx1-i32x8 -DNAME_SUFFIX=avx1 $(ISPC_FLAGS) $< -o $@

$(ISPC_OBJ)/poh-verify-avx2.o: poh-verify.ipsc $(DEPS)
	@mkdir -p $(ISPC_OBJ)
	$(CC) --target=avx2-i32x8 -DNAME_SUFFIX=avx2 $(ISPC_FLAGS) $< -o $@

$(ISPC_OBJ)/poh-verify-avx512skx.o: poh-verify.ipsc $(DEPS)
	@mkdir -p $(ISPC_OBJ)
	$(CC) --target=avx512skx-i32x16 -DNAME_SUFFIX=avx512skx $(ISPC_FLAGS) $< -o $@

$(OUT)/libpoh-simd.a: $(ISPC_C_Objects)
	@mkdir -p $(OUT)
	ar rcs $@ $^

clean:
	@rm -rf $(ISPC_OBJ) $(OUT)
