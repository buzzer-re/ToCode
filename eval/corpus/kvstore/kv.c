#include "kv.h"

#include <stdlib.h>
#include <string.h>

unsigned long kv_hash(const char *key) {
    unsigned long hash = 5381;
    for (const unsigned char *p = (const unsigned char *)key; *p; p++)
        hash = hash * 33 + *p;
    return hash;
}

struct kv_table *kv_new(void) {
    return calloc(1, sizeof(struct kv_table));
}

static struct kv_entry **kv_slot(struct kv_table *table, const char *key) {
    struct kv_entry **slot = &table->buckets[kv_hash(key) % KV_BUCKETS];
    while (*slot && strcmp((*slot)->key, key) != 0)
        slot = &(*slot)->next;
    return slot;
}

void kv_set(struct kv_table *table, const char *key, int value) {
    struct kv_entry **slot = kv_slot(table, key);
    if (*slot) {
        (*slot)->value = value;
        return;
    }
    struct kv_entry *entry = malloc(sizeof(*entry));
    entry->key = strdup(key);
    entry->value = value;
    entry->next = NULL;
    *slot = entry;
    table->count++;
}

int kv_get(const struct kv_table *table, const char *key, int *value) {
    struct kv_entry **slot = kv_slot((struct kv_table *)table, key);
    if (!*slot)
        return 0;
    *value = (*slot)->value;
    return 1;
}

int kv_delete(struct kv_table *table, const char *key) {
    struct kv_entry **slot = kv_slot(table, key);
    struct kv_entry *entry = *slot;
    if (!entry)
        return 0;
    *slot = entry->next;
    free(entry->key);
    free(entry);
    table->count--;
    return 1;
}

void kv_free(struct kv_table *table) {
    for (size_t i = 0; i < KV_BUCKETS; i++) {
        struct kv_entry *entry = table->buckets[i];
        while (entry) {
            struct kv_entry *next = entry->next;
            free(entry->key);
            free(entry);
            entry = next;
        }
    }
    free(table);
}
