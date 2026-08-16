CC ?= gcc
CFLAGS ?= -O1 -g
OUT := ../../build

all: $(OUT)/aes_rng_after_use_strip

$(OUT)/aes_rng_after_use_strip: aes_rng_after_use.c
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) $< -lcrypto -o $(OUT)/aes_rng_after_use
	cp $(OUT)/aes_rng_after_use $@
	strip $@

.PHONY: all
