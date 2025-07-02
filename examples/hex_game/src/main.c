// main.c - vulnerable game server

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <termios.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/time.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "gfx.h"
#include "logic.h"
#include "defs.h"

static struct termios oldt;

void set_raw_mode(int enable) {
    struct termios newt;
    if (enable) {
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    } else {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    }
}

void cleanup(int sig) {
    set_raw_mode(0);
    printf("\nExiting...\n");
    exit(0);
}

char get_input_with_timeout(int timeout_ms) {
    struct timeval tv;
    fd_set fds;
    tv.tv_sec = 0;
    tv.tv_usec = timeout_ms * 1000;

    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);

    if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0) {
        char c;
        read(STDIN_FILENO, &c, 1);
        return c;
    }

    return 0; // No input
}

long current_millis() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

// Hidden RCE target 
void secret() {
    set_raw_mode(0);
    printf("\nSecret function triggered! You've achieved unintended RCE!\n");
    exit(0);
}

void enter_name() {
    char name[64];
    printf("\nEnter your name: ");
    gets(name);                 // classic stack buffer overflow
}

void submit_highscore() {
    char comment[64];
    printf("\nSubmit your score comment: ");
    scanf("%63s", comment);
    printf(comment);            // format string vulnerability
    printf("\nThanks!\n");
}

void win_game(int score) {
    printf("\nYou win! Score reached %d points!\n", score);
    set_raw_mode(0);
    enter_name();
    submit_highscore();
    exit(0);
}

void run_game(int client_fd) {
    Bot bots[MAX_BOTS];
    int bot_count = 0;
    int launch_code = 0;
    unsigned short score = 0;
    char input;

    srand(time(NULL));
    signal(SIGINT, cleanup);
    set_raw_mode(1);

    long last_fall_time = current_millis();
    long last_spawn_time = current_millis();

    while (1) {
        input = get_input_with_timeout(100);

        if (input == 'q') break;

        if (input) {
            launch_code = make_launch_code(launch_code, input);

            int match_index = filter_match(launch_code, bots, &bot_count);
            if (match_index != -1) {
                score += 5;

                if (score == 31337) {
                    secret();
                }

                launch_code = 0;
            }
        }

        long now = current_millis();

        if (now - last_fall_time >= 1000) {
            for (int i = 0; i < bot_count; i++) {
                bots[i].age++;
                if (bots[i].age >= DROP_EVERY) {
                    bots[i].age = 0;
                    bots[i].y++;

                    if (bots[i].y >= GAME_HEIGHT) {
                        set_raw_mode(0);
                        printf("\nA bot hit the ground. Game Over. Final Score: %d\n", score);
                        exit(1);
                    }
                }
            }
            last_fall_time = now;
        }

        if (now - last_spawn_time >= 10000 && bot_count < MAX_BOTS) {
            bots[bot_count++] = new_random_bot();
            last_spawn_time = now;
        }

        draw_screen(bots, bot_count, score, launch_code);

        if (score >= 1000) {
            win_game(score);
        }
    }

    set_raw_mode(0);
}

int main() {
    int sockfd, client_fd;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4444);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    listen(sockfd, 1);

    printf("Game server listening on port 4444...\n");

    client_fd = accept(sockfd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        exit(1);
    }

    dup2(client_fd, STDIN_FILENO);
    dup2(client_fd, STDOUT_FILENO);
    dup2(client_fd, STDERR_FILENO);

    run_game(client_fd);

    close(client_fd);
    close(sockfd);
    return 0;
}
