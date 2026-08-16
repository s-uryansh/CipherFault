OUT := ../../build

all: $(OUT)/non_aes_evp_strip

$(OUT)/non_aes_evp_strip: non_aes_evp.c
	mkdir -p $(OUT)
	gcc -O2 -s $< -o $@ -lcrypto

clean:
	rm -f $(OUT)/non_aes_evp_strip
