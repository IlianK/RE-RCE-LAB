// gfx.c
#include <stdio.h>
#include "defs.h"

static const char* gfxSides = "|                                    |";
static const char* gfxSeperator = "+------------------------------------+";
static const char* gfxWords = "| HEX  | BINARY    | SCORE  | BEST   |";
static const char* gfxGameOver = "|          | GAME OVER |             |";
static const char* gfxGameOverSep = "|          +-----------+             |";

void clear_screen() {
    printf("\033[H\033[2J");
}

void draw_vals(int launch_code, int score) {
    printf("| %02X   | ", launch_code);
    for (int i = 7; i >= 0; i--) {
        printf("%d", (launch_code >> i) & 1);
    }
    printf("  | %05d  | 00000  |\n", score);
}

void draw_main(Bot bots[], int bot_count) {
    for (int i = 0; i < GAME_HEIGHT; i++) {
        char line[40];
        snprintf(line, sizeof(line), "%s", gfxSides);

        for (int j = 0; j < bot_count; j++) {
            if (bots[j].y == i) {
                int pos = bots[j].x;
                int code = bots[j].code;
                line[pos] = '<';
                snprintf(&line[pos + 1], 3, "%02X", code);
                line[pos + 3] = '>';
            }
        }

        printf("%s\n", line);
    }
}

void draw_screen(Bot bots[], int bot_count, int score, int launch_code) {
    clear_screen();
    printf("%s\n", gfxSeperator);
    draw_main(bots, bot_count);
    printf("%s\n", gfxSeperator);
    printf("%s\n", gfxWords);
    draw_vals(launch_code, score);
    printf("%s\n", gfxSeperator);
}
