CC=gcc
CFLAGS=-Wall

all: boot_display

boot_display: boot_display.c
	$(CC) $(CFLAGS) -o boot_display boot_display.c

clean:
	rm -f boot_display

