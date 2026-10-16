/*
 * secret_check.c -- pneuma test binary #1
 *
 * A classic "enter the password" CTF loop. The real password is never
 * stored in plaintext in the binary: it lives XOR-obfuscated in the
 * global array `g_obfuscated_secret` and is only decoded into memory
 * (global buffer `g_decoded_secret`) right before each comparison,
 * then wiped again.
 *
 * Intended pneuma solves (see README.md for the full writeup):
 *   1. symbols.resolve "g_obfuscated_secret" / "g_decoded_secret" / "check_secret"
 *   2. mem.read the obfuscated bytes + g_xor_key, XOR them by hand, or
 *      just wait for a compare and mem.scan text:<guess> / scan the
 *      known decoded window right after decode_secret() runs.
 *   3. disasm check_secret to see the strcmp/loop, or hook.install on
 *      check_secret with a JIT stub that always returns 1 so any input
 *      is GRANTED.
 *
 * Build: dynamically linked, symbols kept (see Makefile).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SECRET_LEN 13

/* "pneuma-rocks!" XORed with key 0x5A, stored obfuscated so a naive
 * `strings` pass over the binary will not reveal it. */
static unsigned char g_obfuscated_secret[SECRET_LEN + 1] = {
    'p'^0x5A, 'n'^0x5A, 'e'^0x5A, 'u'^0x5A, 'm'^0x5A, 'a'^0x5A, '-'^0x5A,
    'r'^0x5A, 'o'^0x5A, 'c'^0x5A, 'k'^0x5A, 's'^0x5A, '!'^0x5A, 0x00
};

static const unsigned char g_xor_key = 0x5A;

/* Decoded secret is parked here in plain memory for a short window on
 * every check -- a good target for mem.scan text:pneuma-rocks or a
 * simple mem.read once the offset is known. */
static char g_decoded_secret[SECRET_LEN + 1];

static void decode_secret(void) {
    for (int i = 0; i < SECRET_LEN; i++) {
        g_decoded_secret[i] = (char)(g_obfuscated_secret[i] ^ g_xor_key);
    }
    g_decoded_secret[SECRET_LEN] = '\0';
}

static void wipe_decoded_secret(void) {
    memset(g_decoded_secret, 0, sizeof(g_decoded_secret));
}

/* Straightforward hook target: an inline hook on check_secret that
 * forces it to return 1 immediately bypasses the whole password check
 * regardless of input. */
int check_secret(const char *input) {
    int ok;
    decode_secret();
    ok = (strcmp(input, g_decoded_secret) == 0);
    wipe_decoded_secret();
    return ok;
}

static void strip_newline(char *s) {
    size_t n = strlen(s);
    if (n > 0 && s[n - 1] == '\n') s[n - 1] = '\0';
}

int main(void) {
    char line[256];

    printf("secret_check starting, pid=%d\n", getpid());
    fflush(stdout);

    for (;;) {
        printf("Enter password: ");
        fflush(stdout);

        if (fgets(line, sizeof(line), stdin) == NULL) {
            /* stdin closed (e.g. launched under run_all.sh with no
             * tty) -- stay alive idling so the process can still be
             * introspected/hooked, just stop hammering the terminal. */
            printf("stdin closed, idling so pneuma can still attach...\n");
            fflush(stdout);
            for (;;) {
                sleep(3);
            }
        }

        strip_newline(line);

        if (check_secret(line)) {
            printf("GRANTED\n");
        } else {
            printf("DENIED\n");
        }
        fflush(stdout);
    }

    return 0;
}
