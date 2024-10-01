#ifndef __PEER_H__
#define __PEER_H__

#include <pthread.h>
#include <stdint.h>
#include <time.h>

#include <libcork/core.h>
#include <libcork/ds.h>

#include "utils.h"

struct peer {
    pthread_mutex_t lck;
    uint32_t destroy;

    char *host;

    struct {
        uint64_t tx;
        uint64_t rx;
    } traffic;
    struct {
        uint64_t tx;
        uint64_t rx;
    } traffic_udp;

    struct {
        uint32_t tcp;
        uint32_t udp;
    } access_cnt;

    struct timespec ts;
};

struct peer_tbl {
    struct cork_hash_table *tbl;
    pthread_spinlock_t lck;
};

static inline struct peer *peer_create(char *peer_name, struct timespec *ts)
{
    struct peer *peer = NULL;

    peer = ss_malloc(sizeof(*peer));
    if (!peer)
        return NULL;

    memset(peer, 0, sizeof(*peer));

    peer->host = ss_malloc(strlen(peer_name) + 1);
    if (!peer->host) {
        free(peer);
        return NULL;
    }

    memset(peer->host, 0, strlen(peer_name) + 1);
    memcpy(peer->host, peer_name, strlen(peer_name));
    peer->ts = *ts;

    pthread_mutex_init(&peer->lck, NULL);

    return peer;
}

static inline int peer_free(struct peer *peer)
{
    int err;

    if (0 == __sync_bool_compare_and_swap(&peer->destroy, 0, 1))
        return -EBUSY;

    if ((err = pthread_mutex_lock(&peer->lck)) != 0)
        return err;

    ss_free(peer->host);

    pthread_mutex_unlock(&peer->lck);

    pthread_mutex_destroy(&peer->lck);
    ss_free(peer);

    return 0;
}

static inline int peer_lock(struct peer *peer)
{
    int err;

    if (!peer)
        return -EINVAL;

    if (peer->destroy)
        return -EBUSY;

    if ((err = pthread_mutex_lock(&peer->lck)) != 0)
        return err;

    return 0;
}

static inline void peer_unlock(struct peer *peer)
{
    pthread_mutex_unlock(&peer->lck);
}

static inline struct peer *peer_create_or_update(struct peer_tbl *tbl, char *peer_name)
{
    struct cork_hash_table_entry *entry = NULL;
    struct timespec ts = {};
    struct peer *peer = NULL;

    clock_gettime(CLOCK_REALTIME, &ts);

    pthread_spin_lock(&tbl->lck);
    entry = cork_hash_table_get_entry(tbl->tbl, peer_name);
    if (!entry) {
        bool is_new = 0; // useless

        peer = peer_create(peer_name, &ts);
        if (!peer)
            goto out;

        cork_hash_table_put(tbl->tbl, peer->host, peer, &is_new, NULL, NULL);
    } else {
        peer = entry->value;
        peer->ts = ts;
    }

out:
    pthread_spin_unlock(&tbl->lck);

    return peer;
}

static inline struct peer *peer_get(struct peer_tbl *tbl, char *peer_name)
{
    struct peer *peer = NULL;
    struct cork_hash_table_entry *entry = NULL;

    pthread_spin_lock(&tbl->lck);
    entry = cork_hash_table_get_entry(tbl->tbl, peer_name);
    if (!entry) {
        LOGE("peer \"%s\" not found in hash table", peer_name);
        goto unlock;
    } else {
        peer = entry->value;
    }

unlock:
    pthread_spin_unlock(&tbl->lck);

    return peer;
}

static inline void peer_tbl_init(struct peer_tbl *tbl)
{
    pthread_spin_init(&tbl->lck, 0);
    tbl->tbl = cork_string_hash_table_new(1024, 0);
}

static inline void peer_tbl_deinit(struct peer_tbl *tbl)
{
    struct cork_hash_table_entry *entry;
    struct cork_hash_table_iterator iter = { };

    if (!tbl)
        return;

    cork_hash_table_iterator_init(tbl->tbl, &iter);

    while ((entry = cork_hash_table_iterator_next(&iter)) != NULL) {
        struct peer *peer = entry->value;
        peer_free(peer);
    }

    cork_hash_table_free(tbl->tbl);
    pthread_spin_destroy(&tbl->lck);
}

#endif // __PEER_H__
