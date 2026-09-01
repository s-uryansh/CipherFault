CC ?= gcc
CFLAGS ?= -O2 -s
LDLIBS ?= -lcrypto

BIN := payment-service.out

all: $(BIN)

$(BIN): payment_service.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

scan: $(BIN)
	PYTHONDONTWRITEBYTECODE=1 ../../.venv/bin/python -m cipherfault.cli scan ./$(BIN) --format json

clean:
	rm -f $(BIN)

.PHONY: all scan clean
