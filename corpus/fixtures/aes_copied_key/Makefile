CC ?= gcc
CFLAGS ?= -O1 -g -fno-omit-frame-pointer
OUT := ../../build

all: $(OUT)/aes_copied_key_strip

$(OUT)/aes_copied_key_strip: aes_copied_key.c
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) $< -lcrypto -o $(OUT)/aes_copied_key
	cp $(OUT)/aes_copied_key $@
	strip $@

.PHONY: all
