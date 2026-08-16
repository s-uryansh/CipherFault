OUT := ../../build

all: $(OUT)/aes_dynamic_operands_strip

$(OUT)/aes_dynamic_operands_strip: aes_dynamic_operands.c
	mkdir -p $(OUT)
	gcc -O2 -s $< -o $@ -lcrypto

clean:
	rm -f $(OUT)/aes_dynamic_operands_strip
