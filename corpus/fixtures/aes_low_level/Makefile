CC ?= gcc
CFLAGS ?= -O1 -g -Wno-deprecated-declarations
OUT := ../../build

all: $(OUT)/aes_low_level_strip

$(OUT)/aes_low_level_strip: aes_low_level.c
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) $< -lcrypto -o $(OUT)/aes_low_level
	cp $(OUT)/aes_low_level $@
	strip $@

.PHONY: all
