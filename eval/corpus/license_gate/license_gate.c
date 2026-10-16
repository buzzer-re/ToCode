/*
 * license_gate.c -- pneuma test binary #3
 *
 * A minimal "software license" gate. check_license() always returns 0
 * (invalid) -- there is no valid license anywhere in this program by
 * design. main() loops calling it and prints "unlicensed" forever.
 *
 * Intended pneuma solve:
 *   1. symbols.resolve "check_license" to get its address.
 *   2. disasm check_license to confirm it is just `mov w0, #0; ret`.
 *   3. hook.install on check_license, redirecting it to a small JIT
 *      stub that does `movz w0, #1; ret` (aarch64) so the function
 *      always returns 1 (truthy) without touching the on-disk binary.
 *   4. Observe main's output flip from "unlicensed" to "LICENSED! all
 *      features unlocked" once the hook is live -- no restart needed.
 *
 * Build: dynamically linked, symbols kept (see Makefile).
 */

#include <stdio.h>
#include <unistd.h>

/* Deliberately trivial and never inlined so it stays a clean, single
 * hookable function -- `noinline` keeps -O2 from folding the whole
 * thing away at the call site. */
__attribute__((noinline))
int check_license(void) {
    return 0; /* always invalid */
}

int main(void) {
    unsigned long tick = 0;

    printf("license_gate starting, pid=%d\n", getpid());
    fflush(stdout);

    for (;;) {
        tick++;
        if (check_license()) {
            printf("[%lu] LICENSED! all features unlocked\n", tick);
        } else {
            printf("[%lu] unlicensed -- running in restricted mode\n", tick);
        }
        fflush(stdout);
        sleep(2);
    }

    return 0;
}
