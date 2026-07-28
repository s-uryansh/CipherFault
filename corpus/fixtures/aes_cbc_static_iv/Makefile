OUT := ../../build
CFLAGS_COMMON := -lcrypto

all: $(OUT)/aes_cbc_static_iv_dbg $(OUT)/aes_cbc_static_iv_strip

$(OUT)/aes_cbc_static_iv_dbg: aes_cbc_static_iv.c
	mkdir -p $(OUT)
	gcc -O0 -g $< -o $@ $(CFLAGS_COMMON)

$(OUT)/aes_cbc_static_iv_strip: aes_cbc_static_iv.c
	mkdir -p $(OUT)
	gcc -O2 -s $< -o $@ $(CFLAGS_COMMON)

clean:
	rm -f $(OUT)/aes_cbc_static_iv_dbg $(OUT)/aes_cbc_static_iv_strip
