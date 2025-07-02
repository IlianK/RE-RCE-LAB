// logic.c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "defs.h"
#include "logic.h"

int make_launch_code(int current, char key) {
    int bit = key - '1';
    bit = 7 - bit;
    if (bit < 0 || bit > 7) return current;
    return current ^ (1 << bit);
}

int filter_match(int launch_code, Bot bots[], int* bot_count) {
    for (int i = 0; i < *bot_count; i++) {
        if (bots[i].code == launch_code) {
            for (int j = i; j < *bot_count - 1; j++) {
                bots[j] = bots[j + 1];
            }
            (*bot_count)--;
            return i;
        }
    }
    return -1;
}

Bot new_random_bot() {
    Bot b;
    b.x = rand() % (GAME_WIDTH - 4) + 1;
    b.y = 0;
    b.age = 0;
    b.code = rand() % 256;
    return b;
}

void bots_tick(Bot bots[], int* bot_count, int score) {
    for (int i = 0; i < *bot_count; i++) {
        bots[i].age++;
        if (bots[i].age >= DROP_EVERY) {
            bots[i].age = 0;
            bots[i].y++;
        }
        if (bots[i].y >= GAME_HEIGHT) {
            printf("\nA bot hit the ground. Game Over. Final Score: %d\n", score);
            exit(1);
        }
    }

    if ((rand() % 100) < 20 && *bot_count < MAX_BOTS) {
        bots[(*bot_count)++] = new_random_bot();
    }
}
