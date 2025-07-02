#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFSIZE 64

// Prototype declarations
void secret();
int generate_password(const char *username);
int read_username(int fd, char *buf, size_t size);
int get_password_input(int fd);
void authenticate_client(int fd, const char *username);
void handle_client(int fd);


// Hidden function
void secret() {
    printf("You've reached the secret function!\n");
    // system("/bin/sh"); 
}

// Trivial password generation algorithm
int generate_password(const char *username) {
    return abs((username[0] + (username[1] << 1) - username[2]) % 10000);
}

// Safe input - name
int read_username(int fd, char *buf, size_t size) {
    write(fd, "Username: ", 10);
    int n = read(fd, buf, size - 1);
    if (n <= 0) return -1;
    buf[n] = '\0';

    if (strlen(buf) < 3) {
        write(fd, "Too short\n", 10);
        return -1;
    }
    return 0;
}

// Vulnerable input — password
int get_password_input(int fd) {
    char pw_input[BUFSIZE];
    dprintf(STDOUT_FILENO, "DEBUG: pw_input @ %p\n", pw_input);
    read(fd, pw_input, 128);  // <-- overflow
    return atoi(pw_input);
}

// Login logic
void authenticate_client(int fd, const char *username) {
    int expected_pw = generate_password(username);
    write(fd, "Password: ", 10);

    int pw_try = get_password_input(fd);

    if (pw_try == expected_pw) {
        write(fd, "Access granted\n", 15);
    } else {
        write(fd, "Access denied\n", 14);
    }
}


// Main logic for each client
void handle_client(int fd) {
    char username[BUFSIZE];

    if (read_username(fd, username, sizeof(username)) == 0) {
        authenticate_client(fd, username);
    }

    close(fd);
}


// TCP Server setup
int main() {
    int sockfd, client_fd;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket failed");
        exit(1);
    }

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(4444);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        exit(1);
    }

    if (listen(sockfd, 1) < 0) {
        perror("listen failed");
        exit(1);
    }

    printf("Listening on port 4444...\n");
    client_fd = accept(sockfd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept failed");
        exit(1);
    }

    handle_client(client_fd);
    close(sockfd);
    return 0;
}
