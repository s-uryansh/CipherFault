OUT := ../../build
CFLAGS := -O1 -g -Wno-deprecated-declarations

all: $(OUT)/rsa_keygen $(OUT)/rsa_keygen_dynamic

$(OUT)/rsa_keygen: rsa_keygen.c
	mkdir -p $(OUT)
	gcc $(CFLAGS) $< -o $@ -lcrypto

$(OUT)/rsa_keygen_dynamic: rsa_keygen.c
	mkdir -p $(OUT)
	gcc $(CFLAGS) -DDYNAMIC_BITS $< -o $@ -lcrypto

clean:
	rm -f $(OUT)/rsa_keygen $(OUT)/rsa_keygen_dynamic
