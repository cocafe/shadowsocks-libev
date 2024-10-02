#ifndef __PEER_H__
#define __PEER_H__

#include <pthread.h>
#include <stdint.h>
#include <time.h>

#include <libcork/core.h>
#include <libcork/ds.h>

#include "utils.h"

enum {
    PEER_STAT_TCP_UNAUTH,
    PEER_STAT_UDP_UNAUTH,
    PEER_STAT_TCP_CONN,
    PEER_STAT_UDP_CONN,
    PEER_STAT_UDP_FRAG,
    PEER_STAT_UDP_INVALID,
    PEER_STAT_TCP_INVALID,
    NUM_PEER_STATS,
};

struct peer {
    pthread_mutex_t lck;
    uint32_t destroy;
    struct timespec ts;

    char *host;

    struct {
        uint64_t tx;
        uint64_t rx;
    } traffic;
    struct {
        uint64_t tx;
        uint64_t rx;
    } traffic_udp;

    uint64_t stats[NUM_PEER_STATS];
};

struct hash_tbl {
    struct cork_hash_table *tbl;
    pthread_spinlock_t lck;
};

enum {
    PEER_CONN_STAT_TCP_TX,
    PEER_CONN_STAT_TCP_RX,
    PEER_CONN_STAT_UDP_TX,
    PEER_CONN_STAT_UDP_RX,
    PEER_CONN_STAT_TCP_CONN,
    PEER_CONN_STAT_UDP_CONN,
    NUM_PEER_CONN_STATS,
};

// port is not tracked
struct peer_conn {
    char *peer;
    char *remote;
    char *key;
    uint64_t stats[NUM_PEER_CONN_STATS];
};

static inline void peer_conn_make_key(char *key, char *peer, char *remote)
{
    sprintf(key, "%s%s", peer, remote);
}

static inline struct peer_conn *peer_conn_create(char *peer, char *remote)
{
    struct peer_conn *p = NULL;

    p = ss_malloc(sizeof(*p));
    if (!p)
        return NULL;

    memset(p, 0, sizeof(*p));;

    p->peer = ss_malloc(strlen(peer) + 2);
    p->remote = ss_malloc(strlen(remote) + 2);
    p->key = ss_malloc(strlen(peer) + strlen(remote) + 2);
    if (!p->peer || !p->remote || !p->key)
        goto free;

    memset(p->peer, '\0', strlen(peer) + 2);
    memset(p->remote, '\0', strlen(remote) + 2);
    memset(p->key, '\0', strlen(peer) + strlen(remote) + 2);

    memcpy(p->peer, peer, strlen(peer));
    memcpy(p->remote, remote, strlen(remote));
    peer_conn_make_key(p->key, peer, remote);

    return p;

free:
    if (p->peer)
        ss_free(p->peer);

    if (p->remote)
        ss_free(p->remote);

    if (p->key)
        ss_free(p->key);

    ss_free(p);

    return NULL;
}

static inline int peer_conn_free(struct peer_conn *p)
{
    if (p->peer)
        ss_free(p->peer);

    if (p->remote)
        ss_free(p->remote);

    if (p->key)
        ss_free(p->key);

    ss_free(p);

    return 0;
}

static inline struct peer_conn *peer_conn_create_or_get(struct hash_tbl *tbl, char *peer, char *remote)
{
    struct cork_hash_table_entry *entry = NULL;
    struct peer_conn *conn;
    char key[256] = { };

    if (!tbl || !peer || !remote)
        return NULL;

    peer_conn_make_key(key, peer, remote);

    pthread_spin_lock(&tbl->lck);
    entry = cork_hash_table_get_entry(tbl->tbl, key);
    if (!entry) {
        bool is_new = 0;

        conn = peer_conn_create(peer, remote);
        if (!conn)
            goto out;

        cork_hash_table_put(tbl->tbl, key, conn, &is_new, NULL, NULL);
    } else {
        conn = entry->value;
    }

out:
    pthread_spin_unlock(&tbl->lck);

    return conn;
}

static inline struct peer_conn *peer_conn_get(struct hash_tbl *tbl, char *peer, char *remote)
{
    struct cork_hash_table_entry *entry = NULL;
    struct peer_conn *conn = NULL;
    char key[256] = { };

    if (!tbl || !peer || !remote)
        return NULL;

    peer_conn_make_key(key, peer, remote);

    pthread_spin_lock(&tbl->lck);
    entry = cork_hash_table_get_entry(tbl->tbl, key);
    if (entry) {
        conn = entry->value;
    }

    pthread_spin_unlock(&tbl->lck);

    return conn;
}

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

    if (peer->host)
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

static inline struct peer *peer_create_or_get(struct hash_tbl *tbl, char *peer_name)
{
    struct cork_hash_table_entry *entry = NULL;
    struct timespec ts = {};
    struct peer *peer = NULL;

    clock_gettime(CLOCK_REALTIME, &ts);

    if (!tbl || !peer_name)
        return NULL;

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

static inline struct peer *peer_get(struct hash_tbl *tbl, char *peer_name)
{
    struct peer *peer = NULL;
    struct cork_hash_table_entry *entry = NULL;

    pthread_spin_lock(&tbl->lck);
    entry = cork_hash_table_get_entry(tbl->tbl, peer_name);
    if (!entry) {
        dump_stack();
        LOGE("peer \"%s\" not found in hash table", peer_name);
        goto unlock;
    } else {
        peer = entry->value;
    }

unlock:
    pthread_spin_unlock(&tbl->lck);

    return peer;
}

static inline void hash_tbl_init(struct hash_tbl *tbl)
{
    pthread_spin_init(&tbl->lck, 0);
    tbl->tbl = cork_string_hash_table_new(1024, 0);
}

static inline void hash_tbl_deinit(struct hash_tbl *tbl)
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
