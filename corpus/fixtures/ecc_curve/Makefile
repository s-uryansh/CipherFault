OUT := ../../build
CFLAGS := -O1 -g -Wno-deprecated-declarations

all: $(OUT)/ecc_curve $(OUT)/ecc_curve_dynamic

$(OUT)/ecc_curve: ecc_curve.c
	mkdir -p $(OUT)
	gcc $(CFLAGS) $< -o $@ -lcrypto

$(OUT)/ecc_curve_dynamic: ecc_curve.c
	mkdir -p $(OUT)
	gcc $(CFLAGS) -DDYNAMIC_CURVE $< -o $@ -lcrypto

clean:
	rm -f $(OUT)/ecc_curve $(OUT)/ecc_curve_dynamic
