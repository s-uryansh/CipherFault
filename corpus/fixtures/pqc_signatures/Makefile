CC ?= gcc
CFLAGS ?= -O1 -g

all: pqc_signatures

pqc_signatures: main.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	$(RM) pqc_signatures
