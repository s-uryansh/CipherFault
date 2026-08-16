OUT := ../../build

all: $(OUT)/digest_md5_strip $(OUT)/digest_sha256_strip

$(OUT)/digest_md5_strip: digest_api.c
	mkdir -p $(OUT)
	gcc -O2 -s -DUSE_MD5 $< -o $@ -lcrypto

$(OUT)/digest_sha256_strip: digest_api.c
	mkdir -p $(OUT)
	gcc -O2 -s $< -o $@ -lcrypto

clean:
	rm -f $(OUT)/digest_md5_strip $(OUT)/digest_sha256_strip
