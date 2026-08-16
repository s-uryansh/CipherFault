OUT := ../../build

all: $(OUT)/aes_unrelated_rand_strip

$(OUT)/aes_unrelated_rand_strip: aes_unrelated_rand.c
	mkdir -p $(OUT)
	gcc -O2 -s $< -o $@ -lcrypto

clean:
	rm -f $(OUT)/aes_unrelated_rand_strip
