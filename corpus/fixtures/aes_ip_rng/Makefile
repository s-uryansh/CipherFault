CC ?= gcc
CFLAGS ?= -O1 -g
OUT := ../../build

all: $(OUT)/aes_ip_rng_strip

$(OUT)/aes_ip_rng_strip: aes_ip_rng.c
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) $< -lcrypto -o $(OUT)/aes_ip_rng
	cp $(OUT)/aes_ip_rng $@
	strip $@

.PHONY: all
