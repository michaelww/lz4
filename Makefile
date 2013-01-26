

CFLAGS = -O3 -g -std=c99 -Wall -Wextra -pedantic
CFLAGS += -save-temps -fverbose-asm

KERN = $(shell uname -s)
ARCH = $(shell arch)

ifneq ($(findstring ppc,$(ARCH)),)
CFLAGS += -maltivec -mabi=altivec

ifeq ($(ARCH),ppc)
CFLAGS += -mcpu=7450
endif
ifeq ($(KERN),Linux)
CFLAGS += -mno-vrsave
endif

endif

default: lz4

rollsum_test: rollsum.o rollsum_test.o

dedup: CFLAGS += -I../blake2s/
dedup: dedup.o rollsum.o ../blake2s/libblake2.so

clean:
	rm -f *.o

.PHONY: clean

# use gcc 4.7 if we can
ifneq ($(shell which gcc-4.7),)
CC = gcc-4.7
endif

blowfish: blowfish.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -DTEST $<

blowfish_gcm: blowfish.o blowfish_gcm.o


