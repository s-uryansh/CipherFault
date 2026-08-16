CC ?= gcc
CFLAGS ?= -O0 -g

all: mlkem_weak_randomness

mlkem_weak_randomness: main.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	$(RM) mlkem_weak_randomness
