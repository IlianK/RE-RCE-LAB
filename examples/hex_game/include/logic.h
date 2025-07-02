#ifndef LOGIC_H
#define LOGIC_H

#include "defs.h"

int make_launch_code(int current, char key);
int filter_match(int launch_code, Bot bots[], int* bot_count);
void bots_tick(Bot bots[], int* bot_count, int score);
Bot new_random_bot(); // ✅ Add this line

#endif
