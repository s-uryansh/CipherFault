OUT := ../../build
CFLAGS_COMMON := -lcrypto

all: $(OUT)/aes_weak_rng_key_dbg $(OUT)/aes_weak_rng_key_strip

$(OUT)/aes_weak_rng_key_dbg: aes_weak_rng_key.c
	mkdir -p $(OUT)
	gcc -O0 -g $< -o $@ $(CFLAGS_COMMON)

$(OUT)/aes_weak_rng_key_strip: aes_weak_rng_key.c
	mkdir -p $(OUT)
	gcc -O2 -s $< -o $@ $(CFLAGS_COMMON)

clean:
	rm -f $(OUT)/aes_weak_rng_key_dbg $(OUT)/aes_weak_rng_key_strip