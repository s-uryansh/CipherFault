CC ?= gcc
CFLAGS ?= -O1 -g
OUT := ../../build

all: $(OUT)/aes_ambiguous_callers_strip

$(OUT)/aes_ambiguous_callers_strip: aes_ambiguous_callers.c
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) $< -lcrypto -o $(OUT)/aes_ambiguous_callers
	cp $(OUT)/aes_ambiguous_callers $@
	strip $@

.PHONY: all
