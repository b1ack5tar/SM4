CC = cc
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -Iinclude

TARGET = sm4
SRC = src/main.c src/sm4.c src/utils.c
OBJ = $(SRC:.c=.o)

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

src/%.o: src/%.c include/sm4.h include/utils.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJ)

test: $(TARGET)
	@test "$$(./sm4 enc-block 0123456789abcdeffedcba9876543210 0123456789abcdeffedcba9876543210)" = "681edf34d206965e86b3e94f536e4246"
	@test "$$(./sm4 dec-block 0123456789abcdeffedcba9876543210 681edf34d206965e86b3e94f536e4246)" = "0123456789abcdeffedcba9876543210"
	@test "$$(./sm4 dec 0123456789abcdeffedcba9876543210 $$(./sm4 enc 0123456789abcdeffedcba9876543210 00112233445566778899aabbccddeeff))" = "00112233445566778899aabbccddeeff"
