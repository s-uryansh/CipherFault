OUT := ../../build
TARGET := $(OUT)/aes_returned_key

all: $(TARGET)_strip

$(TARGET): aes_returned_key.c
	mkdir -p $(OUT)
	gcc -O2 -g $< -lcrypto -o $@

$(TARGET)_strip: $(TARGET)
	cp $< $@
	strip $@

clean:
	rm -f $(TARGET) $(TARGET)_strip
