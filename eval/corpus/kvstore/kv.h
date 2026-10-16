#ifndef KV_H
#define KV_H

#include <stddef.h>

#define KV_BUCKETS 16

struct kv_entry {
    char *key;
    int value;
    struct kv_entry *next;
};

struct kv_table {
    struct kv_entry *buckets[KV_BUCKETS];
    size_t count;
};

unsigned long kv_hash(const char *key);
struct kv_table *kv_new(void);
void kv_set(struct kv_table *table, const char *key, int value);
int kv_get(const struct kv_table *table, const char *key, int *value);
int kv_delete(struct kv_table *table, const char *key);
void kv_free(struct kv_table *table);

#endif
