#ifndef __DB_H
#define __DB_H

#define MAX_DB_NAME_SIZE 32

#include <stdint.h>
#include <stdlib.h>

struct db {
    struct db_entry {
        long hash;
        char name[MAX_DB_NAME_SIZE];
    } *entries;
    size_t size;
    size_t capacity;
};

int db_init(struct db* db);
void db_destroy(struct db* db);
int db_find(struct db* db, long hash, char* name);
int db_insert(struct db* db, long hash, const char* name);

#endif // !__DB_H