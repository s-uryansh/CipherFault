OUT := ../../build
CFLAGS_COMMON := -lcrypto

all: $(OUT)/aes_ecb_demo_dbg $(OUT)/aes_ecb_demo_strip
$(OUT)/aes_ecb_demo_dbg: aes_ecb_demo.c
	mkdir -p $(OUT)
	gcc -O0 -g $< -o $@ $(CFLAGS_COMMON)
$(OUT)/aes_ecb_demo_strip: aes_ecb_demo.c
	mkdir -p $(OUT)
	gcc -O2 -s $< -o $@ $(CFLAGS_COMMON)

clean:
	rm -f $(OUT)/aes_ecb_demo_dbg $(OUT)/aes_ecb_demo_strip