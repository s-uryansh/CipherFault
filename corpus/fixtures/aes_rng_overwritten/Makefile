CC ?= gcc
CFLAGS ?= -O1 -g -fno-omit-frame-pointer -fno-builtin-memset
OUT := ../../build

all: $(OUT)/aes_rng_overwritten_strip

$(OUT)/aes_rng_overwritten_strip: aes_rng_overwritten.c
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) $< -lcrypto -o $(OUT)/aes_rng_overwritten
	cp $(OUT)/aes_rng_overwritten $@
	strip $@

.PHONY: all
