#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum item_kind { KIND_TOOL = 1, KIND_FOOD = 2, KIND_KEY = 3 };

struct item {
    char name[24];
    enum item_kind kind;
    int weight;
    struct item *next;
};

static struct item *g_items;
int g_total_weight;

struct item *item_new(const char *name, enum item_kind kind, int weight) {
    struct item *it = calloc(1, sizeof(*it));
    strncpy(it->name, name, sizeof(it->name) - 1);
    it->kind = kind;
    it->weight = weight;
    return it;
}

void inventory_add(struct item *it) {
    it->next = g_items;
    g_items = it;
    g_total_weight += it->weight;
}

int inventory_count_kind(enum item_kind kind) {
    int n = 0;
    for (struct item *it = g_items; it; it = it->next)
        if (it->kind == kind) n++;
    return n;
}

int main(int argc, char **argv) {
    inventory_add(item_new("hammer", KIND_TOOL, 5));
    inventory_add(item_new("apple", KIND_FOOD, 1));
    inventory_add(item_new(argc > 1 ? argv[1] : "brass key", KIND_KEY, 1));
    printf("tools=%d weight=%d\n", inventory_count_kind(KIND_TOOL), g_total_weight);
    return 0;
}
