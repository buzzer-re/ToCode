/*
 * anti_introspect.c -- pneuma test binary #5
 *
 * Periodically reads its own /proc/self/status and reports whether
 * TracerPid is non-zero ("feels watched") or zero ("feels normal"). It
 * also keeps a canary value and reports if it is ever tampered with.
 *
 * This is intentionally MILD:
 *   - it does NOT call ptrace(PTRACE_TRACEME, ...) (that would make the
 *     process its own tracer and fight/break an injector that relies
 *     on ptrace),
 *   - it never exits or aborts on a "watched" observation, it just
 *     prints what it sees,
 *   - the canary check only prints, it never crashes.
 *
 * Purpose: demonstrate that a pneuma LD_PRELOAD-based agent (loaded
 * into the process's own address space, not attached via ptrace) is
 * invisible to this kind of naive /proc/self/status self-check --
 * TracerPid should stay 0 even while pneuma is actively reading and
 * writing this process's memory over its socket.
 *
 * Intended pneuma solves:
 *   1. symbols.resolve "g_canary" and mem.read it to confirm the
 *      expected value (0xC0FFEE).
 *   2. mem.write g_canary to a different value and watch the next
 *      loop tick print "canary TAMPERED" -- shows that a naive
 *      in-memory integrity check does not stop pneuma, it just proves
 *      pneuma was there.
 *   3. proc.auxv / elf.phdrs / linkmap to inspect process structure
 *      alongside the TracerPid observations, and confirm that
 *      injecting/attaching via pneuma does not flip TracerPid the way
 *      a ptrace-based debugger would.
 *
 * Build: dynamically linked, symbols kept (see Makefile).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CANARY_EXPECTED 0xC0FFEEu

/* A simple integrity canary. pneuma can mem.write this to prove it can
 * modify memory without the process crashing or exiting. */
volatile unsigned int g_canary = CANARY_EXPECTED;

static long read_tracer_pid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long tracer_pid = -1;

    if (!f) return -1;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer_pid = strtol(line + 10, NULL, 10);
            break;
        }
    }
    fclose(f);
    return tracer_pid;
}

int main(void) {
    unsigned long tick = 0;

    printf("anti_introspect starting, pid=%d\n", getpid());
    printf("canary expected value: 0x%06X\n", CANARY_EXPECTED);
    fflush(stdout);

    for (;;) {
        tick++;
        long tp = read_tracer_pid();

        if (tp > 0) {
            printf("[%lu] TracerPid=%ld -- feels watched (a ptrace tracer is attached)\n",
                   tick, tp);
        } else if (tp == 0) {
            printf("[%lu] TracerPid=0 -- feels normal (no ptrace tracer visible)\n", tick);
        } else {
            printf("[%lu] could not read TracerPid\n", tick);
        }

        if (g_canary != CANARY_EXPECTED) {
            printf("[%lu] canary TAMPERED: now 0x%06X (expected 0x%06X) -- "
                   "someone wrote to our memory!\n",
                   tick, g_canary, CANARY_EXPECTED);
        } else {
            printf("[%lu] canary intact (0x%06X)\n", tick, g_canary);
        }

        fflush(stdout);
        sleep(2);
    }

    return 0;
}
