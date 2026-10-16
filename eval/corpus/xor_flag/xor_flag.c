/*
 * xor_flag.c -- pneuma test binary #2
 *
 * Holds a CTF-style flag XOR-encoded in a global array. Every few
 * seconds a decode cycle copies the plaintext flag into a global
 * scratch buffer for a short "visible window", then zeroes it again.
 * The program never prints the flag itself -- only a hint that a
 * decode just happened -- so the only way to read it is to catch it
 * in memory during that window.
 *
 * Intended pneuma solves:
 *   1. symbols.resolve "g_flag_window" (the visible-window buffer) and
 *      "g_encoded_flag" / "g_flag_key".
 *   2. mem.scan text:flag{ in a tight polling loop to catch the plain
 *      text while g_flag_window is populated, OR
 *   3. mem.read g_encoded_flag + g_flag_key once and XOR-decode it
 *      offline (the key never changes and is trivial to read even
 *      when the window is zeroed).
 *
 * Build: dynamically linked, symbols kept (see Makefile).
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define FLAG_LEN 22

/* "flag{pneuma_sees_all}" XORed with key 0xA5 */
static unsigned char g_encoded_flag[FLAG_LEN + 1] = {
    'f'^0xA5,'l'^0xA5,'a'^0xA5,'g'^0xA5,'{'^0xA5,
    'p'^0xA5,'n'^0xA5,'e'^0xA5,'u'^0xA5,'m'^0xA5,'a'^0xA5,'_'^0xA5,
    's'^0xA5,'e'^0xA5,'e'^0xA5,'s'^0xA5,'_'^0xA5,
    'a'^0xA5,'l'^0xA5,'l'^0xA5,'}'^0xA5, 0
};

static const unsigned char g_flag_key = 0xA5;

/* Populated in plaintext for ~1 second every decode cycle, then
 * scrubbed. This is the memory-scan target. */
static char g_flag_window[FLAG_LEN + 1];

static void decode_flag_into_window(void) {
    for (int i = 0; i < FLAG_LEN; i++) {
        g_flag_window[i] = (char)(g_encoded_flag[i] ^ g_flag_key);
    }
    g_flag_window[FLAG_LEN] = '\0';
}

static void scrub_window(void) {
    memset(g_flag_window, 0, sizeof(g_flag_window));
}

int main(void) {
    unsigned long cycle = 0;

    printf("xor_flag starting, pid=%d\n", getpid());
    printf("hint: the flag is XOR-encoded at rest and only exists in\n");
    printf("plaintext for a short window in g_flag_window after each decode.\n");
    fflush(stdout);

    for (;;) {
        cycle++;
        decode_flag_into_window();
        printf("[cycle %lu] flag decoded into memory for ~1s...\n", cycle);
        fflush(stdout);

        usleep(1000 * 1000); /* ~1s visible window */

        scrub_window();
        printf("[cycle %lu] window scrubbed.\n", cycle);
        fflush(stdout);

        sleep(3); /* quiet period before next decode */
    }

    return 0;
}
