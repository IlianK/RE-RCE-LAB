// defs.h
#ifndef DEFS_H
#define DEFS_H

#define MAX_BOTS 50
#define GAME_WIDTH 36
#define GAME_HEIGHT 20
#define DROP_EVERY 12  // drop every 1.5 seconds at 8 ticks/sec

typedef struct {
    int x;
    int y;
    int age;
    int code;
} Bot;

#endif
