CC ?= gcc
CFLAGS ?= -O1 -g
OUT := ../../build

all: $(OUT)/verification_ignored_strip $(OUT)/verification_checked_strip

$(OUT)/verification_ignored_strip: verification_outcome.c
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) $< -lcrypto -o $(OUT)/verification_ignored
	cp $(OUT)/verification_ignored $@
	strip $@

$(OUT)/verification_checked_strip: verification_outcome.c
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) -DCHECK_RESULT $< -lcrypto -o $(OUT)/verification_checked
	cp $(OUT)/verification_checked $@
	strip $@

.PHONY: all
