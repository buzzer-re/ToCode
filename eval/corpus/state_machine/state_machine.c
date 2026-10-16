/*
 * state_machine.c -- pneuma test binary #4
 *
 * A tiny state machine driven entirely by the global `int state`
 * (mirrored inside the global struct g_machine for a slightly richer
 * target). Each loop iteration prints behavior based on the current
 * state, and occasionally advances itself -- but an external write to
 * `state` (or `g_machine.state`) via mem.write takes effect
 * immediately on the next loop tick.
 *
 * State -> behavior mapping (also see README.md):
 *   STATE_IDLE    (0) -> prints "idle: waiting for work"
 *   STATE_RUNNING (1) -> prints "running: processing job #N"
 *   STATE_PAUSED  (2) -> prints "paused: holding position"
 *   STATE_ERROR   (3) -> prints "error: something went wrong (code=g_machine.error_code)"
 *   STATE_DONE    (4) -> prints "done: shutting down cleanly" then
 *                         loops back to STATE_IDLE (never really exits,
 *                         so the process stays alive for inspection)
 *
 * Intended pneuma solves:
 *   1. symbols.resolve "state" (or "g_machine") to find its address.
 *   2. mem.read state / g_machine to observe the current value & the
 *      struct layout (state, job_counter, error_code).
 *   3. mem.write state to an arbitrary valid (or even invalid, e.g. 99)
 *      value and watch the printed behavior change/react on the next
 *      tick -- demonstrates live state coercion without hooking code.
 *
 * Build: dynamically linked, symbols kept (see Makefile).
 */

#include <stdio.h>
#include <unistd.h>

enum {
    STATE_IDLE = 0,
    STATE_RUNNING = 1,
    STATE_PAUSED = 2,
    STATE_ERROR = 3,
    STATE_DONE = 4
};

/* Plain global int -- the simplest possible mem.write target. */
int state = STATE_IDLE;

/* Richer struct target with the same state value duplicated in
 * g_machine.state, plus a couple of companion fields. */
struct machine {
    int state;
    int job_counter;
    int error_code;
};

struct machine g_machine = { STATE_IDLE, 0, 0 };

static void sync_machine(void) {
    /* Keep the plain global and the struct copy consistent so either
     * one can be used as the mem.write target interchangeably. */
    g_machine.state = state;
}

int main(void) {
    printf("state_machine starting, pid=%d\n", getpid());
    printf("states: 0=IDLE 1=RUNNING 2=PAUSED 3=ERROR 4=DONE\n");
    fflush(stdout);

    for (;;) {
        sync_machine();

        switch (state) {
            case STATE_IDLE:
                printf("idle: waiting for work\n");
                state = STATE_RUNNING; /* auto-advance */
                break;

            case STATE_RUNNING:
                g_machine.job_counter++;
                printf("running: processing job #%d\n", g_machine.job_counter);
                if (g_machine.job_counter % 3 == 0) {
                    state = STATE_PAUSED;
                }
                break;

            case STATE_PAUSED:
                printf("paused: holding position\n");
                state = STATE_RUNNING; /* resume next tick */
                break;

            case STATE_ERROR:
                printf("error: something went wrong (code=%d)\n",
                       g_machine.error_code);
                state = STATE_IDLE; /* self-heal */
                break;

            case STATE_DONE:
                printf("done: shutting down cleanly\n");
                state = STATE_IDLE; /* loop back, stay alive */
                break;

            default:
                printf("unknown state %d (externally forced?) -- treating as ERROR\n",
                       state);
                g_machine.error_code = state;
                state = STATE_ERROR;
                break;
        }

        fflush(stdout);
        sleep(1);
    }

    return 0;
}
