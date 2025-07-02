# hex_game_score/Makefile

CC = gcc
CFLAGS = -Iinclude -fno-stack-protector -no-pie -z execstack
SRC = src/main.c src/gfx.c src/logic.c
BIN = build/hex_game_score

all: build $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $(BIN) $(SRC)

build:
	mkdir -p build

clean:
	rm -rf build
