#include <db.h>

int db_init(struct db* db) {
    db->size = 0;
    db->capacity = 16;
    db->entries = malloc(db->capacity * sizeof(struct db_entry));
    if (db->entries == NULL) {
        return -1;
    }
    return 0;
}

void db_destroy(struct db* db) {
    free(db->entries);
}

int db_find(struct db* db, long hash, char* name) {
    for (size_t i = 0; i < db->size; i++) {
        if (db->entries[i].hash == hash) {
            strncpy(name, db->entries[i].name, MAX_DB_NAME_SIZE);
            return 0;
        }
    }
    return -1;
}

int db_insert(struct db* db, long hash, const char* name) {
    if (db->size == db->capacity) {
        db->capacity *= 2;
        db->entries = realloc(db->entries, db->capacity * sizeof(struct db_entry));
        if (db->entries == NULL) {
            return -1;
        }
    }
    db->entries[db->size].hash = hash;
    strncpy(db->entries[db->size].name, name, MAX_DB_NAME_SIZE);
    db->size++;
    return 0;
}