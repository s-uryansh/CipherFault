CC ?= gcc
CFLAGS ?= -O1 -g

all: mlkem_api

mlkem_api: main.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	$(RM) mlkem_api
