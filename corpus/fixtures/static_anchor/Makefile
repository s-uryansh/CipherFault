OUT := ../../build

all: $(OUT)/static_anchor_reference $(OUT)/static_anchor_target \
	$(OUT)/static_anchor_cross_reference $(OUT)/static_anchor_cross_target

$(OUT)/static_anchor_crypto.a: crypto.c
	mkdir -p $(OUT)
	gcc -O2 -c $< -o $(OUT)/static_anchor_crypto.o
	ar rcs $@ $(OUT)/static_anchor_crypto.o

$(OUT)/static_anchor_reference: reference.c $(OUT)/static_anchor_crypto.a
	gcc -O2 -g $^ -o $@

$(OUT)/static_anchor_target: target.c $(OUT)/static_anchor_crypto.a
	gcc -O2 -s $^ -o $@

$(OUT)/static_anchor_cross_reference: reference.c crypto.c
	gcc-12 -O1 -g -fcf-protection=full $^ -o $@

$(OUT)/static_anchor_cross_target: target.c crypto.c
	clang -O3 -s -fcf-protection=none $^ -o $@

clean:
	rm -f $(OUT)/static_anchor_crypto.o $(OUT)/static_anchor_crypto.a \
		$(OUT)/static_anchor_reference $(OUT)/static_anchor_target \
		$(OUT)/static_anchor_cross_reference $(OUT)/static_anchor_cross_target
