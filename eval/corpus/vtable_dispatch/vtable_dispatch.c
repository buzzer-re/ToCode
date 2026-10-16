/*
 * vtable_dispatch.c -- pneuma test binary #6
 *
 * A hand-rolled "vtable": a global array of function pointers that
 * main() dispatches through in a round-robin loop. This complements
 * inline-hooking targets (like license_gate/secret_check) with a
 * function-POINTER hooking target: instead of patching code bytes at
 * the callee, an agent can overwrite an entry in g_vtable itself so
 * the *same call site* jumps somewhere else entirely.
 *
 * Intended pneuma solves:
 *   1. symbols.resolve "g_vtable", "handler_alpha", "handler_beta",
 *      "handler_gamma", "handler_redirect_target".
 *   2. mem.read g_vtable (an array of 3 pointers) to see the current
 *      targets, and disasm each handler_* to confirm they are
 *      distinct, simple functions.
 *   3. mem.write one g_vtable[i] slot's 8 bytes (aarch64 pointer
 *      width) to the address of handler_redirect_target (or any other
 *      handler) -- next dispatch through that slot silently calls the
 *      new function instead, no inline hook needed.
 *   4. Observe the printed "handler ran" name change on the next
 *      cycle to confirm the redirect took effect live.
 *
 * Build: dynamically linked, symbols kept (see Makefile).
 */

#include <stdio.h>
#include <unistd.h>

typedef void (*handler_fn)(unsigned long tick);

__attribute__((noinline))
void handler_alpha(unsigned long tick) {
    printf("[%lu] handler ran: alpha (the boring default)\n", tick);
}

__attribute__((noinline))
void handler_beta(unsigned long tick) {
    printf("[%lu] handler ran: beta (does slightly more work)\n", tick);
}

__attribute__((noinline))
void handler_gamma(unsigned long tick) {
    printf("[%lu] handler ran: gamma (the last of the original three)\n", tick);
}

/* Not referenced by g_vtable at startup -- only reachable if an agent
 * writes its address into one of the vtable slots. A good "did the
 * redirect actually happen" signal. */
__attribute__((noinline))
void handler_redirect_target(unsigned long tick) {
    printf("[%lu] handler ran: REDIRECT_TARGET (a pointer was overwritten!)\n", tick);
}

#define VTABLE_SIZE 3

handler_fn g_vtable[VTABLE_SIZE] = {
    handler_alpha,
    handler_beta,
    handler_gamma,
};

int main(void) {
    unsigned long tick = 0;

    printf("vtable_dispatch starting, pid=%d\n", getpid());
    printf("g_vtable has %d slots, dispatched round-robin\n", VTABLE_SIZE);
    fflush(stdout);

    for (;;) {
        tick++;
        handler_fn h = g_vtable[tick % VTABLE_SIZE];
        h(tick);
        fflush(stdout);
        sleep(2);
    }

    return 0;
}
