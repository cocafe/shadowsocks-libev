#ifndef __PEER_H__
#define __PEER_H__

#include <stdint.h>
#include <time.h>

struct peer {
    char *host;
    struct {
        uint64_t tx;
        uint64_t rx;
    } traffic;
    struct {
        uint64_t tx;
        uint64_t rx;
    } traffic_udp;
    struct timespec ts;
};

extern struct peer *peer_create_or_update(char *peer_name);
extern struct peer *peer_get(char *peer_name);

#endif // __PEER_H__
