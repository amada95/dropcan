#
#	Makefile
#

CC		= gcc
CFLAGS	= -Wall -Wextra -Wpedantic -std=c99 -O2
LFLAGS	= -lcap -lseccomp

CSRC	= dropcan.c
TARGET	= dropcan.bin

TEST_SRC	= dropcan_test.c
TEST_TARGET	= dropcan_test.bin
TEST_CFLAGS	= -Wall -Werror -static -std=c99 -O2

build:
	@$(CC) -o $(TARGET) $(CSRC) $(CFLAGS) $(LFLAGS)

test:
	@$(CC) -o $(TEST_TARGET) $(TEST_SRC) $(TEST_CFLAGS)
	sudo ./$(TARGET) -m . -u 0 -c $(TEST_TARGET)

clean:
	rm $(TARGET) $(TEST_TARGET)
