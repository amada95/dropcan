#
#	Makefile
#

CC		= gcc
CFLAGS	= -Wall -Wextra -Wpedantic -Werror -std=c99 -O2
LFLAGS	= -lcap -lseccomp
CSRC	= dropcan.c
TARGET	= dropcan.bin

all:
	@$(CC) -o $(TARGET) $(CSRC) $(CFLAGS) $(LFLAGS)

clean:
	rm $(TARGET)
