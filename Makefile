OS := $(shell uname)

all:
ifeq ($(OS),Darwin)
SO=dylib
else
SO=so
all: cuda_crypt
endif

V=Release

BUILD_DIR=src/build
.PHONY:cuda_crypt
cuda_crypt:
	mkdir -p $(BUILD_DIR) && cd $(BUILD_DIR) && cmake -DCMAKE_BUILD_TYPE=$(V) .. && $(MAKE) -j

DESTDIR ?= dist
install:
	mkdir -p $(DESTDIR)
ifneq ($(OS),Darwin)
	cp -f $(BUILD_DIR)/libcuda-crypt.so $(DESTDIR)
endif
	ls -lh $(DESTDIR)

.PHONY:clean
clean:
	rm -rf $(BUILD_DIR)
