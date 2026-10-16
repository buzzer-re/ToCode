/* Reads commands from stdin: set KEY VALUE, get KEY, del KEY, count. */
#include <stdio.h>
#include <string.h>

#include "kv.h"

static int run_command(struct kv_table *table, char *line) {
    char key[64];
    int value;
    if (sscanf(line, "set %63s %d", key, &value) == 2) {
        kv_set(table, key, value);
        printf("ok\n");
    } else if (sscanf(line, "get %63s", key) == 1) {
        if (kv_get(table, key, &value))
            printf("%s=%d\n", key, value);
        else
            printf("%s: missing\n", key);
    } else if (sscanf(line, "del %63s", key) == 1) {
        printf(kv_delete(table, key) ? "deleted\n" : "missing\n");
    } else if (strncmp(line, "count", 5) == 0) {
        printf("%zu\n", table->count);
    } else {
        printf("unknown command\n");
        return -1;
    }
    return 0;
}

int main(void) {
    struct kv_table *table = kv_new();
    char line[256];
    int errors = 0;
    while (fgets(line, sizeof(line), stdin))
        if (run_command(table, line) != 0)
            errors++;
    kv_free(table);
    return errors ? 1 : 0;
}
