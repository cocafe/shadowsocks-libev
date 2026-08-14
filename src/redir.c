/*
 * redir.c - Provide a transparent TCP proxy through remote shadowsocks
 *           server
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

#include <libcork/core.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "plugin.h"
#include "netutils.h"
#include "utils.h"
#include "common.h"
#include "redir.h"
#include "prometheus.h"
#include "prom_remote.h"
#include "peer.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT       19
#endif

#ifndef IPV6_TRANSPARENT
#define IPV6_TRANSPARENT     75
#endif

static void accept_cb(EV_P_ ev_io *w, int revents);
static void server_recv_cb(EV_P_ ev_io *w, int revents);
static void server_send_cb(EV_P_ ev_io *w, int revents);
static void remote_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_send_cb(EV_P_ ev_io *w, int revents);

static remote_t *new_remote(int fd, int timeout);
static server_t *new_server(int fd);

static void free_remote(remote_t *remote);
static void close_and_free_remote(EV_P_ remote_t *remote);
static void free_server(server_t *server);
static void close_and_free_server(EV_P_ server_t *server);

static ss_addr_t g_remote_addr[MAX_REMOTE_NUM];

int verbose    = 0;
int reuse_port = 0;
int tcp_incoming_sndbuf = 0;
int tcp_incoming_rcvbuf = 0;
int tcp_outgoing_sndbuf = 0;
int tcp_outgoing_rcvbuf = 0;

static crypto_t *crypto;

static int ipv6first = 0;
static int mode      = TCP_ONLY;
#ifdef HAVE_SETRLIMIT
static int nofile = 0;
#endif
int fast_open       = 0;
static int no_delay = 0;
static int ret_val  = 0;

static struct ev_signal sigint_watcher;
static struct ev_signal sigterm_watcher;
static struct ev_signal sigchld_watcher;

static uint64_t remote_name_resolve_intv_ms = 600 * 1000;

static int tcp_tproxy = 0; /* use tproxy instead of redirect (for tcp) */

#ifndef PEER_CONN_IDLE_TIMEOUT
#define PEER_CONN_IDLE_TIMEOUT 600
#endif

static time_t conn_clean_timeout = PEER_CONN_IDLE_TIMEOUT;

static uint32_t metric_port = 0;
static uint32_t metric_conntrack = 0;
static uint32_t metric_conncount = 0;
static int metrics_enabled = 0;

static sem_t sem_prom_update;
static pthread_t tid_prom_server;
static pthread_t tid_prom_update;

static prom_metric_def metric_ss_tx = { "ss_redir_tx", "Total TX bytes", PROM_METRIC_TYPE_COUNTER };
static prom_metric_def metric_ss_rx = { "ss_redir_rx", "Total RX bytes", PROM_METRIC_TYPE_COUNTER };
static prom_metric_def metric_ss_conn = { "ss_redir_conn", "Connection count", PROM_METRIC_TYPE_COUNTER };
static prom_metric_def metric_conn_tx = { "ss_redir_conn_tx", "Connection TX bytes", PROM_METRIC_TYPE_COUNTER };
static prom_metric_def metric_conn_rx = { "ss_redir_conn_rx", "Connection RX bytes", PROM_METRIC_TYPE_COUNTER };
static prom_metric_def metric_conn_cnt = { "ss_redir_conn_cnt", "Per-connection count", PROM_METRIC_TYPE_COUNTER };
static prom_metric_set metrics;

static struct hash_tbl conn_tbl;

static char redir_port_str[16] = { };

static int remote_conn = 0;
static int local_conn = 0;
static uint64_t tx_bytes = 0;
static uint64_t rx_bytes = 0;

static int
getdestaddr(int fd, struct sockaddr_storage *destaddr)
{
    socklen_t socklen = sizeof(*destaddr);
    int error         = 0;

    if (tcp_tproxy) {
        error = getsockname(fd, (void *)destaddr, &socklen);
    } else {
        error = getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, destaddr, &socklen);
        if (error) { // Didn't find a proper way to detect IP version.
            error = getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, destaddr, &socklen);
        }
    }

    if (error) {
        return -1;
    }
    return 0;
}

static int
format_local_addr(int fd, char *buf, size_t len)
{
    struct sockaddr_storage addr;
    socklen_t socklen = sizeof(struct sockaddr_storage);

    memset(&addr, 0, socklen);

    if (getpeername(fd, (struct sockaddr *)&addr, &socklen) != 0)
        return -1;

    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&addr;
        char ip[INET_ADDRSTRLEN] = { 0 };
        if (!inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip)))
            return -1;
        snprintf(buf, len, "%s", ip);
        return 0;
    } else if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
        char ip[INET6_ADDRSTRLEN] = { 0 };
        if (!inet_ntop(AF_INET6, &s->sin6_addr, ip, sizeof(ip)))
            return -1;
        snprintf(buf, len, "%s", ip);
        return 0;
    }

    return -1;
}

static int
format_destaddr(const struct sockaddr_storage *addr, char *buf, size_t len)
{
    if (addr->ss_family == AF_INET) {
        struct sockaddr_in *sa = (struct sockaddr_in *)addr;
        char ip[INET_ADDRSTRLEN] = { 0 };
        if (!inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip)))
            return -1;
        snprintf(buf, len, "%s:%u", ip, ntohs(sa->sin_port));
        return 0;
    } else if (addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)addr;
        char ip[INET6_ADDRSTRLEN] = { 0 };
        if (!inet_ntop(AF_INET6, &sa->sin6_addr, ip, sizeof(ip)))
            return -1;
        snprintf(buf, len, "[%s]:%u", ip, ntohs(sa->sin6_port));
        return 0;
    }

    return -1;
}

static struct peer_conn *
conn_get_or_create_locked(struct hash_tbl *tbl, char *local, char *remote)
{
    struct cork_hash_table_entry *entry;
    struct peer_conn *conn;
    char key[256] = { };
    char *heap_key;

    snprintf(key, sizeof(key), "%s|%s", local, remote);

    entry = cork_hash_table_get_entry(tbl->tbl, key);
    if (entry)
        return entry->value;

    heap_key = ss_malloc(strlen(key) + 1);
    if (!heap_key)
        return NULL;

    strcpy(heap_key, key);

    conn = peer_conn_create(local, remote);
    if (!conn) {
        ss_free(heap_key);
        return NULL;
    }

    bool is_new = 0;
    cork_hash_table_put(tbl->tbl, heap_key, conn, &is_new, NULL, NULL);

    return conn;
}

static void
conn_tx_add(server_t *server, ssize_t bytes)
{
    struct peer_conn *conn;

    if (!metrics_enabled || metric_conntrack == 0)
        return;

    if (!server->local_name || !server->remote_name)
        return;

    pthread_spin_lock(&conn_tbl.lck);
    conn = conn_get_or_create_locked(&conn_tbl, server->local_name,
                                     server->remote_name);
    if (conn) {
        conn->stats[PEER_CONN_STAT_TCP_TX] += bytes;
        clock_gettime(CLOCK_REALTIME, &conn->ts);
    }
    pthread_spin_unlock(&conn_tbl.lck);
}

static void
conn_rx_add(server_t *server, ssize_t bytes)
{
    struct peer_conn *conn;

    if (!metrics_enabled || metric_conntrack == 0)
        return;

    if (!server->local_name || !server->remote_name)
        return;

    pthread_spin_lock(&conn_tbl.lck);
    conn = conn_get_or_create_locked(&conn_tbl, server->local_name,
                                     server->remote_name);
    if (conn) {
        conn->stats[PEER_CONN_STAT_TCP_RX] += bytes;
        clock_gettime(CLOCK_REALTIME, &conn->ts);
    }
    pthread_spin_unlock(&conn_tbl.lck);
}

static void
conn_count_add(server_t *server)
{
    struct peer_conn *conn;

    if (!metrics_enabled || metric_conntrack == 0)
        return;

    if (!server->local_name || !server->remote_name)
        return;

    pthread_spin_lock(&conn_tbl.lck);
    conn = conn_get_or_create_locked(&conn_tbl, server->local_name,
                                     server->remote_name);
    if (conn) {
        conn->stats[PEER_CONN_STAT_TCP_CONN]++;
        clock_gettime(CLOCK_REALTIME, &conn->ts);
    }
    pthread_spin_unlock(&conn_tbl.lck);
}

int
setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int
create_and_bind(const char *addr, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, listen_sock = -1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;   /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */

    result = NULL;

    s = getaddrinfo(addr, port, &hints, &result);
    if (s != 0) {
        LOGI("getaddrinfo: addr: %s port: %s, %s", addr, port, gai_strerror(s));
        return -1;
    }

    if (result == NULL) {
        LOGE("Could not bind");
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_sock == -1) {
            continue;
        }

        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
        if (reuse_port) {
            int err = set_reuseport(listen_sock);
            if (err == 0) {
                LOGI("tcp port reuse enabled");
            }
        }

        if (tcp_tproxy) {
            int level = 0, optname = 0;
            if (rp->ai_family == AF_INET) {
                level = IPPROTO_IP;
                optname = IP_TRANSPARENT;
            } else {
                level = IPPROTO_IPV6;
                optname = IPV6_TRANSPARENT;
            }

            if (setsockopt(listen_sock, level, optname, &opt, sizeof(opt)) != 0) {
                ERROR("setsockopt IP_TRANSPARENT");
                exit(EXIT_FAILURE);
            }
            LOGI("tcp tproxy mode enabled");
        }

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            ERROR("bind");
        }

        close(listen_sock);
        listen_sock = -1;
    }

    freeaddrinfo(result);

    return listen_sock;
}

static void
server_recv_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;

    ev_timer_stop(EV_A_ & server->delayed_connect_watcher);

    ssize_t r = recv(server->fd, remote->buf->data + remote->buf->len,
                     SOCKET_BUF_SIZE - remote->buf->len, 0);

    if (r == 0) {
        // connection closed
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            if (errno == ECONNRESET && verbose)
                LOGI("server recv: %s\n", strerror(errno));
            else
                ERROR("server recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    remote->buf->len += r;
    tx_bytes += r;
    conn_tx_add(server, r);

    if (verbose) {
        uint16_t port = 0;
        char ipstr[INET6_ADDRSTRLEN];
        memset(&ipstr, 0, INET6_ADDRSTRLEN);

        if (AF_INET == server->destaddr.ss_family) {
            struct sockaddr_in *sa = (struct sockaddr_in *)&(server->destaddr);
            inet_ntop(AF_INET, &(sa->sin_addr), ipstr, INET_ADDRSTRLEN);
            port = ntohs(sa->sin_port);
        } else {
            struct sockaddr_in6 *sa = (struct sockaddr_in6 *)&(server->destaddr);
            inet_ntop(AF_INET6, &(sa->sin6_addr), ipstr, INET6_ADDRSTRLEN);
            port = ntohs(sa->sin6_port);
        }

        LOGI("redir to %s:%d, len=%zu, recv=%zd", ipstr, port, remote->buf->len, r);
    }

    if (!remote->send_ctx->connected) {
        ev_io_stop(EV_A_ & server_recv_ctx->io);
        ev_io_start(EV_A_ & remote->send_ctx->io);
        return;
    }

    int err = crypto->encrypt(remote->buf, server->e_ctx, SOCKET_BUF_SIZE);

    if (err) {
        LOGE("invalid password or cipher");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }

    int s = send(remote->fd, remote->buf->data, remote->buf->len, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & server_recv_ctx->io);
            ev_io_start(EV_A_ & remote->send_ctx->io);
            return;
        } else {
            ERROR("send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if (s < remote->buf->len) {
        remote->buf->len -= s;
        remote->buf->idx  = s;
        ev_io_stop(EV_A_ & server_recv_ctx->io);
        ev_io_start(EV_A_ & remote->send_ctx->io);
        return;
    } else {
        remote->buf->idx = 0;
        remote->buf->len = 0;
    }
}

static void
server_send_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_send_ctx = (server_ctx_t *)w;
    server_t *server              = server_send_ctx->server;
    remote_t *remote              = server->remote;
    if (server->buf->len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf->data + server->buf->idx,
                         server->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < server->buf->len) {
            // partly sent, move memory, wait for the next time to send
            server->buf->len -= s;
            server->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            server->buf->len = 0;
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & server_send_ctx->io);
            ev_io_start(EV_A_ & remote->recv_ctx->io);
        }
    }
}

static void
delayed_connect_cb(EV_P_ ev_timer *watcher, int revents)
{
    server_t *server = cork_container_of(watcher, server_t,
                                         delayed_connect_watcher);
    remote_t *remote = server->remote;

    int r = connect(remote->fd, remote->addr,
                    get_sockaddr_len(remote->addr));

    remote->addr = NULL;

    if (r == -1 && errno != CONNECT_IN_PROGRESS) {
        ERROR("connect");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // listen to remote connected event
        ev_io_start(EV_A_ & remote->send_ctx->io);
        ev_timer_start(EV_A_ & remote->send_ctx->watcher);
    }
}

static void
remote_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    remote_ctx_t *remote_ctx
        = cork_container_of(watcher, remote_ctx_t, watcher);

    remote_t *remote = remote_ctx->remote;
    server_t *server = remote->server;

    ev_timer_stop(EV_A_ watcher);

    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}

static void
remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_recv_ctx->remote;
    server_t *server              = remote->server;

    ssize_t r = recv(remote->fd, server->buf->data, SOCKET_BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            if (errno == ECONNRESET && verbose)
                LOGI("remote recv: %s\n", strerror(errno));
            else
                ERROR("remote recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    server->buf->len = r;
    rx_bytes += r;
    conn_rx_add(server, r);

    int err = crypto->decrypt(server->buf, server->d_ctx, SOCKET_BUF_SIZE);
    if (err == CRYPTO_ERROR || err == CRYPTO_SALT) {
        LOGE("invalid password or cipher");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (err == CRYPTO_NEED_MORE) {
        return; // Wait for more
    }

    int s = send(server->fd, server->buf->data, server->buf->len, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_recv_ctx->io);
            ev_io_start(EV_A_ & server->send_ctx->io);
        } else {
            ERROR("send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if (s < server->buf->len) {
        server->buf->len -= s;
        server->buf->idx  = s;
        ev_io_stop(EV_A_ & remote_recv_ctx->io);
        ev_io_start(EV_A_ & server->send_ctx->io);
    }

    // Disable TCP_NODELAY after the first response are sent
    if (!remote->recv_ctx->connected && !no_delay) {
        int opt = 0;
        setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
    }
    remote->recv_ctx->connected = 1;
}

static void
remote_send_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_send_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_send_ctx->remote;
    server_t *server              = remote->server;

    ev_timer_stop(EV_A_ & remote_send_ctx->watcher);

    if (!remote_send_ctx->connected) {
        int r = 0;
        if (remote->addr == NULL) {
            struct sockaddr_storage addr;
            memset(&addr, 0, sizeof(struct sockaddr_storage));
            socklen_t len = sizeof addr;
            r = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
        }
        if (r == 0) {
            remote_send_ctx->connected = 1;

            ev_io_stop(EV_A_ & remote_send_ctx->io);
            ev_io_stop(EV_A_ & server->recv_ctx->io);
            ev_io_start(EV_A_ & remote->recv_ctx->io);

            // send destaddr
            buffer_t ss_addr_to_send;
            buffer_t *abuf = &ss_addr_to_send;
            balloc(abuf, SOCKET_BUF_SIZE);

            if (AF_INET6 == server->destaddr.ss_family) { // IPv6
                abuf->data[abuf->len++] = 4;          // Type 4 is IPv6 address

                size_t in6_addr_len = sizeof(struct in6_addr);
                memcpy(abuf->data + abuf->len,
                       &(((struct sockaddr_in6 *)&(server->destaddr))->sin6_addr),
                       in6_addr_len);
                abuf->len += in6_addr_len;
                memcpy(abuf->data + abuf->len,
                       &(((struct sockaddr_in6 *)&(server->destaddr))->sin6_port),
                       2);
            } else {                             // IPv4
                abuf->data[abuf->len++] = 1; // Type 1 is IPv4 address

                size_t in_addr_len = sizeof(struct in_addr);
                memcpy(abuf->data + abuf->len,
                       &((struct sockaddr_in *)&(server->destaddr))->sin_addr, in_addr_len);
                abuf->len += in_addr_len;
                memcpy(abuf->data + abuf->len,
                       &((struct sockaddr_in *)&(server->destaddr))->sin_port, 2);
            }

            abuf->len += 2;

            int err = crypto->encrypt(abuf, server->e_ctx, SOCKET_BUF_SIZE);
            if (err) {
                LOGE("invalid password or cipher");
                bfree(abuf);
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }

            err = crypto->encrypt(remote->buf, server->e_ctx, SOCKET_BUF_SIZE);
            if (err) {
                LOGE("invalid password or cipher");
                bfree(abuf);
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }

            bprepend(remote->buf, abuf, SOCKET_BUF_SIZE);
            bfree(abuf);
        } else {
            ERROR("getpeername");
            // not connected
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    if (remote->buf->len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        int s = -1;

        if (remote->addr != NULL) {
#if defined(TCP_FASTOPEN_CONNECT)
            int optval = 1;
            if (setsockopt(remote->fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT,
                           (void *)&optval, sizeof(optval)) < 0)
                FATAL("failed to set TCP_FASTOPEN_CONNECT");
            s = connect(remote->fd, remote->addr, get_sockaddr_len(remote->addr));
            if (s == 0)
                s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
#elif defined(MSG_FASTOPEN)
            s = sendto(remote->fd, remote->buf->data + remote->buf->idx,
                       remote->buf->len, MSG_FASTOPEN, remote->addr,
                       get_sockaddr_len(remote->addr));
#else
            FATAL("tcp fast open is not supported on this platform");
#endif

            remote->addr = NULL;

            if (s == -1) {
                if (errno == CONNECT_IN_PROGRESS) {
                    ev_io_start(EV_A_ & remote_send_ctx->io);
                    ev_timer_start(EV_A_ & remote_send_ctx->watcher);
                } else {
                    if (errno == EOPNOTSUPP || errno == EPROTONOSUPPORT ||
                        errno == ENOPROTOOPT) {
                        fast_open = 0;
                        LOGE("fast open is not supported on this platform");
                    } else {
                        ERROR("fast_open_connect");
                    }
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                }
                return;
            }
        } else {
            s = send(remote->fd, remote->buf->data + remote->buf->idx,
                     remote->buf->len, 0);
        }

        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("send");
                // close and free
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < remote->buf->len) {
            // partly sent, move memory, wait for the next time to send
            remote->buf->len -= s;
            remote->buf->idx += s;
            ev_io_start(EV_A_ & remote_send_ctx->io);
            return;
        } else {
            // all sent out, wait for reading
            remote->buf->len = 0;
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_send_ctx->io);
            ev_io_start(EV_A_ & server->recv_ctx->io);
        }
    }
}

static remote_t *
new_remote(int fd, int timeout)
{
    remote_conn++;

    remote_t *remote = ss_malloc(sizeof(remote_t));
    memset(remote, 0, sizeof(remote_t));

    remote->recv_ctx = ss_malloc(sizeof(remote_ctx_t));
    remote->send_ctx = ss_malloc(sizeof(remote_ctx_t));
    remote->buf      = ss_malloc(sizeof(buffer_t));
    balloc(remote->buf, SOCKET_BUF_SIZE);
    memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
    memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
    remote->fd                  = fd;
    remote->recv_ctx->remote    = remote;
    remote->recv_ctx->connected = 0;
    remote->send_ctx->remote    = remote;
    remote->send_ctx->connected = 0;

    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);
    ev_timer_init(&remote->send_ctx->watcher, remote_timeout_cb,
                  min(MAX_CONNECT_TIMEOUT, timeout), 0);

    return remote;
}

static void
free_remote(remote_t *remote)
{
    if (remote->server != NULL) {
        remote->server->remote = NULL;
    }
    if (remote->buf != NULL) {
        bfree(remote->buf);
        ss_free(remote->buf);
    }
    ss_free(remote->recv_ctx);
    ss_free(remote->send_ctx);
    ss_free(remote);
}

static void
close_and_free_remote(EV_P_ remote_t *remote)
{
    if (remote != NULL) {
        ev_timer_stop(EV_A_ & remote->send_ctx->watcher);
        ev_io_stop(EV_A_ & remote->send_ctx->io);
        ev_io_stop(EV_A_ & remote->recv_ctx->io);
        close(remote->fd);
        free_remote(remote);
        remote_conn--;
    }
}

static server_t *
new_server(int fd)
{
    local_conn++;

    server_t *server = ss_malloc(sizeof(server_t));
    memset(server, 0, sizeof(server_t));

    server->recv_ctx = ss_malloc(sizeof(server_ctx_t));
    server->send_ctx = ss_malloc(sizeof(server_ctx_t));
    server->buf      = ss_malloc(sizeof(buffer_t));
    balloc(server->buf, SOCKET_BUF_SIZE);
    memset(server->recv_ctx, 0, sizeof(server_ctx_t));
    memset(server->send_ctx, 0, sizeof(server_ctx_t));
    server->fd                  = fd;
    server->recv_ctx->server    = server;
    server->recv_ctx->connected = 0;
    server->send_ctx->server    = server;
    server->send_ctx->connected = 0;

    server->e_ctx = ss_malloc(sizeof(cipher_ctx_t));
    server->d_ctx = ss_malloc(sizeof(cipher_ctx_t));
    crypto->ctx_init(crypto->cipher, server->e_ctx, 1);
    crypto->ctx_init(crypto->cipher, server->d_ctx, 0);

    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);

    ev_timer_init(&server->delayed_connect_watcher, delayed_connect_cb, 0.05,
                  0);

    return server;
}

static void
free_server(server_t *server)
{
    if (server->remote != NULL) {
        server->remote->server = NULL;
    }
    if (server->e_ctx != NULL) {
        crypto->ctx_release(server->e_ctx);
        ss_free(server->e_ctx);
    }
    if (server->d_ctx != NULL) {
        crypto->ctx_release(server->d_ctx);
        ss_free(server->d_ctx);
    }
    if (server->buf != NULL) {
        bfree(server->buf);
        ss_free(server->buf);
    }
    if (server->local_name)
        ss_free(server->local_name);
    if (server->remote_name)
        ss_free(server->remote_name);
    ss_free(server->recv_ctx);
    ss_free(server->send_ctx);
    ss_free(server);
}

static void
close_and_free_server(EV_P_ server_t *server)
{
    if (server != NULL) {
        ev_io_stop(EV_A_ & server->send_ctx->io);
        ev_io_stop(EV_A_ & server->recv_ctx->io);
        ev_timer_stop(EV_A_ & server->delayed_connect_watcher);
        close(server->fd);
        free_server(server);
        local_conn--;
    }
}

static void
accept_cb(EV_P_ ev_io *w, int revents)
{
    listen_ctx_t *listener = (listen_ctx_t *)w;
    struct sockaddr_storage destaddr;
    memset(&destaddr, 0, sizeof(struct sockaddr_storage));

    int err;

    int serverfd = accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }

    err = getdestaddr(serverfd, &destaddr);
    if (err) {
        LOGE("getdestaddr: %s, %s", print_sockaddr(&destaddr), strerror(errno));
        return;
    }

    setnonblocking(serverfd);
    int opt = 1;
    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    if (tcp_incoming_sndbuf > 0) {
        setsockopt(serverfd, SOL_SOCKET, SO_SNDBUF, &tcp_incoming_sndbuf, sizeof(int));
    }

    if (tcp_incoming_rcvbuf > 0) {
        setsockopt(serverfd, SOL_SOCKET, SO_RCVBUF, &tcp_incoming_rcvbuf, sizeof(int));
    }

    int index = rand() % listener->remote_num;

    if (remote_name_resolve_intv_ms > 0) {
        if (listener->remote_last_resolve_ts[index] &&
            (millis() - *listener->remote_last_resolve_ts[index] >= remote_name_resolve_intv_ms)) {
            char *host = g_remote_addr[index].host;
            char *port = g_remote_addr[index].port;
            struct sockaddr_storage *storage = ss_malloc(sizeof(struct sockaddr_storage));
            memset(storage, 0, sizeof(struct sockaddr_storage));
            if (get_sockaddr(host, port, storage, 1, ipv6first) == -1)  {
                LOGE("failed to resolve latest remote hostname for %s", host);
                ss_free(storage);
            } else {
                if (0 != memcmp(listener->remote_addr[index], storage, sizeof(struct sockaddr_storage))) {
                    LOGE("remote %s new address: %s", host, print_sockaddr(storage));
                }

                if (listener->remote_addr[index])
                    ss_free(listener->remote_addr[index]);

                listener->remote_addr[index] = (struct sockaddr *)storage;
                *listener->remote_last_resolve_ts[index] = millis();
            }
        }
    }

    struct sockaddr *remote_addr = listener->remote_addr[index];
    int protocol = IPPROTO_TCP;
    if (listener->mptcp < 0) {
        protocol = IPPROTO_MPTCP; // Enable upstream MPTCP
    }
    int remotefd = socket(remote_addr->sa_family, SOCK_STREAM, protocol);
    if (remotefd == -1) {
        ERROR("socket");
        return;
    }

    // Set flags
    setsockopt(remotefd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(remotefd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    // Enable TCP keepalive feature
    int keepAlive    = 1;
    int keepIdle     = 40;
    int keepInterval = 20;
    int keepCount    = 5;
    setsockopt(remotefd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepAlive, sizeof(keepAlive));
    setsockopt(remotefd, SOL_TCP, TCP_KEEPIDLE, (void *)&keepIdle, sizeof(keepIdle));
    setsockopt(remotefd, SOL_TCP, TCP_KEEPINTVL, (void *)&keepInterval, sizeof(keepInterval));
    setsockopt(remotefd, SOL_TCP, TCP_KEEPCNT, (void *)&keepCount, sizeof(keepCount));

    // Set non blocking
    setnonblocking(remotefd);

    if (listener->tos >= 0) {
        int rc = setsockopt(remotefd, IPPROTO_IP, IP_TOS, &listener->tos, sizeof(listener->tos));
        if (rc < 0 && errno != ENOPROTOOPT) {
            LOGE("setting ipv4 dscp failed: %d", errno);
        }
#ifdef IPV6_TCLASS
        rc = setsockopt(remotefd, IPPROTO_IPV6, IPV6_TCLASS, &listener->tos, sizeof(listener->tos));
        if (rc < 0 && errno != ENOPROTOOPT) {
            LOGE("setting ipv6 dscp failed: %d", errno);
        }
#endif
    }

    // Enable out-of-tree MPTCP
    if (listener->mptcp > 1) {
        int err = setsockopt(remotefd, SOL_TCP, listener->mptcp, &opt, sizeof(opt));
        if (err == -1) {
            ERROR("failed to enable out-of-tree multipath TCP");
        }
    } else if (listener->mptcp == 1) {
        int i = 0;
        while ((listener->mptcp = mptcp_enabled_values[i]) > 0) {
            int err = setsockopt(remotefd, SOL_TCP, listener->mptcp, &opt, sizeof(opt));
            if (err != -1) {
                break;
            }
            i++;
        }
        if (listener->mptcp == 0) {
            ERROR("failed to enable out-of-tree multipath TCP");
        }
    }

    if (tcp_outgoing_sndbuf > 0) {
        setsockopt(remotefd, SOL_SOCKET, SO_SNDBUF, &tcp_outgoing_sndbuf, sizeof(int));
    }

    if (tcp_outgoing_rcvbuf > 0) {
        setsockopt(remotefd, SOL_SOCKET, SO_RCVBUF, &tcp_outgoing_rcvbuf, sizeof(int));
    }

    server_t *server = new_server(serverfd);
    remote_t *remote = new_remote(remotefd, listener->timeout);
    server->remote   = remote;
    remote->server   = server;
    server->destaddr = destaddr;

    if (metrics_enabled && metric_conntrack != 0) {
        char local_name[INET6_ADDRSTRLEN + 16] = { 0 };
        if (format_local_addr(serverfd, local_name, sizeof(local_name)) == 0) {
            server->local_name = ss_malloc(strlen(local_name) + 1);
            strcpy(server->local_name, local_name);
        }

        char remote_name[INET6_ADDRSTRLEN + 16] = { 0 };
        if (format_destaddr(&destaddr, remote_name, sizeof(remote_name)) == 0) {
            server->remote_name = ss_malloc(strlen(remote_name) + 1);
            strcpy(server->remote_name, remote_name);
        }
    }

    conn_count_add(server);

    if (fast_open) {
        // save remote addr for fast open
        remote->addr = remote_addr;
        ev_timer_start(EV_A_ & server->delayed_connect_watcher);
    } else {
        int r = connect(remotefd, remote_addr, get_sockaddr_len(remote_addr));

        if (r == -1 && errno != CONNECT_IN_PROGRESS) {
            ERROR("connect");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
        // listen to remote connected event
        ev_io_start(EV_A_ & remote->send_ctx->io);
        ev_timer_start(EV_A_ & remote->send_ctx->watcher);
    }
    ev_io_start(EV_A_ & server->recv_ctx->io);
}

static void
signal_cb(EV_P_ ev_signal *w, int revents)
{
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
        case SIGCHLD:
            if (!is_plugin_running()) {
                LOGE("plugin service exit unexpectedly");
                ret_val = -1;
            } else
                return;
        case SIGINT:
        case SIGTERM:
            ev_signal_stop(EV_DEFAULT, &sigint_watcher);
            ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
            ev_signal_stop(EV_DEFAULT, &sigchld_watcher);

            ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }
}

static void *
prom_server_worker(void *arg)
{
    int *should_stop = arg;

    LOGI("metric server running at %s:%u", "0.0.0.0", metric_port);

    if (prom_start_server(&metrics, metric_port, should_stop) < 0)
        FATAL("failed to start prometheus metric server");

    return NULL;
}

static void
metric_ss_stat_update(void)
{
    {
        prom_label label_port = { "redir_port", redir_port_str };
        prom_metric *m = prom_get(&metrics, &metric_ss_tx, 1, label_port);
        m->value = tx_bytes;
    }

    {
        prom_label label_port = { "redir_port", redir_port_str };
        prom_metric *m = prom_get(&metrics, &metric_ss_rx, 1, label_port);
        m->value = rx_bytes;
    }

    {
        prom_label label_type = { "type", "remote" };
        prom_label label_port = { "redir_port", redir_port_str };
        prom_metric *m = prom_get(&metrics, &metric_ss_conn, 2, label_type, label_port);
        m->value = remote_conn;
    }

    {
        prom_label label_type = { "type", "local" };
        prom_label label_port = { "redir_port", redir_port_str };
        prom_metric *m = prom_get(&metrics, &metric_ss_conn, 2, label_type, label_port);
        m->value = local_conn;
    }
}

static int
metric_conn_match(prom_metric *m, struct peer_conn *conn)
{
    if (m->num_labels != 4)
        return 0;

    if (strcmp(m->labels[0].key, "local") || strcmp(m->labels[0].value, conn->peer))
        return 0;
    if (strcmp(m->labels[1].key, "remote") || strcmp(m->labels[1].value, conn->remote))
        return 0;
    if (strcmp(m->labels[2].key, "proto") || strcmp(m->labels[2].value, "tcp"))
        return 0;
    if (strcmp(m->labels[3].key, "redir_port") || strcmp(m->labels[3].value, redir_port_str))
        return 0;

    return 1;
}

static int
metric_conn_def(prom_metric_def *d)
{
    if (d == &metric_conn_tx || d == &metric_conn_rx)
        return 1;

    if (metric_conncount && d == &metric_conn_cnt)
        return 1;

    return 0;
}

static void
metric_conn_del(struct peer_conn *conn)
{
    for (int i = 0; i < metrics.n_defs; i++) {
        prom_metric_def_set *ds = metrics.defs[i];
        prom_metric *m, *n;

        if (!metric_conn_def(ds->def))
            continue;

        list_for_each_entry_safe(m, n, &ds->metrics, node) {
            if (metric_conn_match(m, conn))
                prom_del(m);
        }
    }
}

static void
metric_conn_txrx_update(struct peer_conn *conn)
{
    prom_label label_local = { "local", conn->peer };
    prom_label label_remote = { "remote", conn->remote };
    prom_label label_tcp = { "proto", "tcp" };
    prom_label label_port = { "redir_port", redir_port_str };

    if (conn->stats[PEER_CONN_STAT_TCP_TX]) {
        prom_metric *m = prom_get(&metrics, &metric_conn_tx, 4,
                                  label_local, label_remote, label_tcp, label_port);
        m->value = conn->stats[PEER_CONN_STAT_TCP_TX];
    }

    if (conn->stats[PEER_CONN_STAT_TCP_RX]) {
        prom_metric *m = prom_get(&metrics, &metric_conn_rx, 4,
                                  label_local, label_remote, label_tcp, label_port);
        m->value = conn->stats[PEER_CONN_STAT_TCP_RX];
    }
}

static void
metric_conn_count_update(struct peer_conn *conn)
{
    prom_label label_local = { "local", conn->peer };
    prom_label label_remote = { "remote", conn->remote };
    prom_label label_tcp = { "proto", "tcp" };
    prom_label label_port = { "redir_port", redir_port_str };

    if (conn->stats[PEER_CONN_STAT_TCP_CONN]) {
        prom_metric *m = prom_get(&metrics, &metric_conn_cnt, 4,
                                  label_local, label_remote, label_tcp, label_port);
        m->value = conn->stats[PEER_CONN_STAT_TCP_CONN];
    }
}

static void
metric_conn_update(struct hash_tbl *tbl)
{
    struct cork_hash_table_entry *entry = NULL;
    struct cork_hash_table_iterator iter = {};

    pthread_spin_lock(&tbl->lck);

    cork_hash_table_iterator_init(tbl->tbl, &iter);

    while ((entry = cork_hash_table_iterator_next(&iter)) != NULL) {
        struct peer_conn *conn = entry->value;

        metric_conn_txrx_update(conn);

        if (metric_conncount)
            metric_conn_count_update(conn);
    }

    pthread_spin_unlock(&tbl->lck);
}

static enum cork_hash_table_map_result
conn_tbl_cleanup_mapper(void *user_data, struct cork_hash_table_entry *entry)
{
    struct timespec *now = user_data;
    struct peer_conn *conn = entry->value;

    if (now->tv_sec - conn->ts.tv_sec >= conn_clean_timeout) {
        metric_conn_del(conn);
        free(entry->key);
        peer_conn_free(conn);
        return CORK_HASH_TABLE_MAP_DELETE;
    }

    return CORK_HASH_TABLE_MAP_CONTINUE;
}

static void
conn_tbl_cleanup(struct hash_tbl *tbl)
{
    struct timespec now = {};

    clock_gettime(CLOCK_REALTIME, &now);

    pthread_spin_lock(&tbl->lck);
    cork_hash_table_map(tbl->tbl, &now, conn_tbl_cleanup_mapper);
    pthread_spin_unlock(&tbl->lck);
}

static enum cork_hash_table_map_result
conn_tbl_deinit_mapper(void *user_data, struct cork_hash_table_entry *entry)
{
    struct peer_conn *conn = entry->value;

    (void)user_data;

    metric_conn_del(conn);
    free(entry->key);
    peer_conn_free(conn);
    return CORK_HASH_TABLE_MAP_DELETE;
}

static void
conn_tbl_deinit(struct hash_tbl *tbl)
{
    pthread_spin_lock(&tbl->lck);
    cork_hash_table_map(tbl->tbl, NULL, conn_tbl_deinit_mapper);
    cork_hash_table_free(tbl->tbl);
    pthread_spin_unlock(&tbl->lck);
    pthread_spin_destroy(&tbl->lck);
}

static void *
prom_update_worker(void *arg)
{
    int *should_stop = arg;

    sleep(1);

    while (!*should_stop) {
        struct timespec ts = { };

        metric_ss_stat_update();

        if (metric_conntrack) {
            conn_tbl_cleanup(&conn_tbl);
            metric_conn_update(&conn_tbl);
        }

        if (metric_port != 0)
            prom_flush(&metrics);

        if (prom_remote_enabled()) {
            int err = prom_remote_write(&metrics);
            if (err)
                LOGI("prometheus remote write failed: %s", strerror(-err));
        }

        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 10;

        if (sem_timedwait(&sem_prom_update, &ts) != 0) {
            if (errno != ETIMEDOUT)
                LOGI("sem_timedwait(): %d %s\n", errno, strerror(errno));
        }
    }

    return NULL;
}

int
main(int argc, char **argv)
{
    srand(time(NULL));

    int i, c;
    int pid_flags    = 0;
    int mptcp        = 0;
    int mtu          = 0;
    int should_stop  = 0;
    char *user       = NULL;
    char *local_port = NULL;
    char *local_addr = NULL;
    char *password   = NULL;
    char *key        = NULL;
    char *timeout    = NULL;
    char *method     = NULL;
    char *pid_path   = NULL;
    char *conf_path  = NULL;
    char *str_metric_port = NULL;
    char *str_metric_conntrack = NULL;
    char *str_metric_conncount = NULL;

    char *plugin      = NULL;
    char *plugin_opts = NULL;
    char *plugin_host = NULL;
    char *plugin_port = NULL;
    char tmp_port[8];

    int dscp_num    = 0;
    ss_dscp_t *dscp = NULL;

    int remote_num    = 0;
    char *remote_port = NULL;

    static struct option long_options[] = {
        { "fast-open",   no_argument,       NULL, GETOPT_VAL_FAST_OPEN   },
        { "mtu",         required_argument, NULL, GETOPT_VAL_MTU         },
        { "mptcp",       no_argument,       NULL, GETOPT_VAL_MPTCP       },
        { "plugin",      required_argument, NULL, GETOPT_VAL_PLUGIN      },
        { "plugin-opts", required_argument, NULL, GETOPT_VAL_PLUGIN_OPTS },
        { "reuse-port",  no_argument,       NULL, GETOPT_VAL_REUSE_PORT  },
        { "tcp-incoming-sndbuf", required_argument, NULL, GETOPT_VAL_TCP_INCOMING_SNDBUF },
        { "tcp-incoming-rcvbuf", required_argument, NULL, GETOPT_VAL_TCP_INCOMING_RCVBUF },
        { "tcp-outgoing-sndbuf", required_argument, NULL, GETOPT_VAL_TCP_OUTGOING_SNDBUF },
        { "tcp-outgoing-rcvbuf", required_argument, NULL, GETOPT_VAL_TCP_OUTGOING_RCVBUF },
        { "no-delay",    no_argument,       NULL, GETOPT_VAL_NODELAY     },
        { "password",    required_argument, NULL, GETOPT_VAL_PASSWORD    },
        { "key",         required_argument, NULL, GETOPT_VAL_KEY         },
        { "prom-remote-addr", required_argument, NULL, 'R'               },
        { "prom-remote-port", required_argument, NULL, 'Q'               },
        { "prom-remote-instance", required_argument, NULL, 'J'           },
        { "help",        no_argument,       NULL, GETOPT_VAL_HELP        },
        { "comment",     required_argument, NULL, GETOPT_VAL_DUMMY       },
        { NULL,          0,                 NULL, 0                      }
    };

    opterr = 0;

    USE_TTY();

    while ((c = getopt_long(argc, argv, "f:s:p:l:k:t:m:c:b:a:n:D:M:C:R:Q:J:huUTv6Aj",
                            long_options, NULL)) != -1) {
        switch (c) {
        case GETOPT_VAL_FAST_OPEN:
            fast_open = 1;
            break;
        case GETOPT_VAL_MTU:
            mtu = atoi(optarg);
            LOGI("set MTU to %d", mtu);
            break;
        case GETOPT_VAL_MPTCP:
            mptcp = get_mptcp(1);
            if (mptcp)
                LOGI("enable multipath TCP (%s)", mptcp > 0 ? "out-of-tree" : "upstream");
            break;
        case GETOPT_VAL_NODELAY:
            no_delay = 1;
            LOGI("enable TCP no-delay");
            break;
        case GETOPT_VAL_PLUGIN:
            plugin = optarg;
            break;
        case GETOPT_VAL_PLUGIN_OPTS:
            plugin_opts = optarg;
            break;
        case GETOPT_VAL_KEY:
            key = optarg;
            break;
        case GETOPT_VAL_DUMMY:
            break;
        case GETOPT_VAL_REUSE_PORT:
            reuse_port = 1;
            break;
        case GETOPT_VAL_TCP_INCOMING_SNDBUF:
            tcp_incoming_sndbuf = atoi(optarg);
            break;
        case GETOPT_VAL_TCP_INCOMING_RCVBUF:
            tcp_incoming_rcvbuf = atoi(optarg);
            break;
        case GETOPT_VAL_TCP_OUTGOING_SNDBUF:
            tcp_outgoing_sndbuf = atoi(optarg);
            break;
        case GETOPT_VAL_TCP_OUTGOING_RCVBUF:
            tcp_outgoing_rcvbuf = atoi(optarg);
            break;
        case 's':
            if (remote_num < MAX_REMOTE_NUM) {
                parse_addr(optarg, &g_remote_addr[remote_num++]);
            }
            break;
        case 'p':
            remote_port = optarg;
            break;
        case 'l':
            local_port = optarg;
            break;
        case 'M':
            str_metric_port = optarg;
            break;
        case 'C':
            conn_clean_timeout = atoi(optarg);
            break;
        case 'R':
            prom_remote_set_addr(optarg);
            break;
        case 'Q':
            prom_remote_set_port((uint16_t)atoi(optarg));
            break;
        case 'J':
            prom_remote_set_instance(optarg);
            break;
        case 'j':
            metric_conncount = 1;
            metric_conntrack = 1;
            break;
        case GETOPT_VAL_PASSWORD:
        case 'k':
            password = optarg;
            break;
        case 'f':
            pid_flags = 1;
            pid_path  = optarg;
            break;
        case 't':
            timeout = optarg;
            break;
        case 'm':
            method = optarg;
            break;
        case 'c':
            conf_path = optarg;
            break;
        case 'b':
            local_addr = optarg;
            break;
        case 'a':
            user = optarg;
            break;
#ifdef HAVE_SETRLIMIT
        case 'n':
            nofile = atoi(optarg);
            break;
#endif
        case 'u':
            mode = TCP_AND_UDP;
            break;
        case 'U':
            mode = UDP_ONLY;
            break;
        case 'T':
            tcp_tproxy = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case GETOPT_VAL_HELP:
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        case '6':
            ipv6first = 1;
            break;
        case 'D':
            remote_name_resolve_intv_ms = atoi(optarg);
            break;
        case 'A':
            FATAL("One time auth has been deprecated. Try AEAD ciphers instead.");
            break;
        case '?':
            // The option character is not recognized.
            LOGE("Unrecognized option: %s", optarg);
            opterr = 1;
            break;
        }
    }

    if (opterr) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (argc == 1) {
        if (conf_path == NULL) {
            conf_path = get_default_conf();
        }
    }

    if (conf_path != NULL) {
        jconf_t *conf = read_jconf(conf_path);
        if (remote_num == 0) {
            remote_num = conf->remote_num;
            for (i = 0; i < remote_num; i++)
                g_remote_addr[i] = conf->remote_addr[i];
        }
        if (remote_port == NULL) {
            remote_port = conf->remote_port;
        }
        if (str_metric_port == NULL) {
            str_metric_port = conf->metric_port;
        }
        if (str_metric_conntrack == NULL) {
            str_metric_conntrack = conf->metric_conntrack;
        }
        if (str_metric_conncount == NULL) {
            str_metric_conncount = conf->metric_conncount;
        }
        if (local_addr == NULL) {
            local_addr = conf->local_addr;
        }
        if (local_port == NULL) {
            local_port = conf->local_port;
        }
        if (password == NULL) {
            password = conf->password;
        }
        if (key == NULL) {
            key = conf->key;
        }
        if (method == NULL) {
            method = conf->method;
        }
        if (timeout == NULL) {
            timeout = conf->timeout;
        }
        if (user == NULL) {
            user = conf->user;
        }
        if (plugin == NULL) {
            plugin = conf->plugin;
        }
        if (plugin_opts == NULL) {
            plugin_opts = conf->plugin_opts;
        }
        if (mode == TCP_ONLY) {
            mode = conf->mode;
        }
        if (tcp_tproxy == 0) {
            tcp_tproxy = conf->tcp_tproxy;
        }
        if (mtu == 0) {
            mtu = conf->mtu;
        }
        if (mptcp == 0) {
            mptcp = conf->mptcp;
        }
        if (no_delay == 0) {
            no_delay = conf->no_delay;
        }
        if (reuse_port == 0) {
            reuse_port = conf->reuse_port;
        }
        if (tcp_incoming_sndbuf == 0) {
            tcp_incoming_sndbuf = conf->tcp_incoming_sndbuf;
        }
        if (tcp_incoming_rcvbuf == 0) {
            tcp_incoming_rcvbuf = conf->tcp_incoming_rcvbuf;
        }
        if (tcp_outgoing_sndbuf == 0) {
            tcp_outgoing_sndbuf = conf->tcp_outgoing_sndbuf;
        }
        if (tcp_outgoing_rcvbuf == 0) {
            tcp_outgoing_rcvbuf = conf->tcp_outgoing_rcvbuf;
        }
        if (fast_open == 0) {
            fast_open = conf->fast_open;
        }
#ifdef HAVE_SETRLIMIT
        if (nofile == 0) {
            nofile = conf->nofile;
        }
#endif
        if (ipv6first == 0) {
            ipv6first = conf->ipv6_first;
        }
        dscp_num = conf->dscp_num;
        dscp     = conf->dscp;
    }

    if (remote_num == 0 || remote_port == NULL || local_port == NULL
        || (password == NULL && key == NULL)) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (plugin != NULL) {
        uint16_t port = get_local_port();
        if (port == 0) {
            FATAL("failed to find a free port");
        }
        snprintf(tmp_port, 8, "%d", port);
        if (is_ipv6only(g_remote_addr, remote_num, ipv6first)) {
            plugin_host = "::1";
        } else {
            plugin_host = "127.0.0.1";
        }
        plugin_port = tmp_port;

        LOGI("plugin \"%s\" enabled", plugin);
    }

    if (method == NULL) {
        method = "chacha20-ietf-poly1305";
    }

    if (timeout == NULL) {
        timeout = "600";
    }

#ifdef HAVE_SETRLIMIT
    /*
     * no need to check the return value here since we will show
     * the user an error message if setrlimit(2) fails
     */
    if (nofile > 1024) {
        if (verbose) {
            LOGI("setting NOFILE to %d", nofile);
        }
        set_nofile(nofile);
    }
#endif

    if (local_addr == NULL) {
        if (is_ipv6only(g_remote_addr, remote_num, ipv6first)) {
            local_addr = "::1";
        } else {
            local_addr = "127.0.0.1";
        }
    }

    if (fast_open == 1) {
#ifdef TCP_FASTOPEN
        LOGI("using tcp fast open");
#else
        LOGE("tcp fast open is not supported by this environment");
        fast_open = 0;
#endif
    }

    USE_SYSLOG(argv[0], pid_flags);
    if (pid_flags) {
        daemonize(pid_path);
    }

    if (no_delay) {
        LOGI("enable TCP no-delay");
    }

    if (ipv6first) {
        LOGI("resolving hostname to IPv6 address first");
    }

    if (tcp_incoming_sndbuf != 0 && tcp_incoming_sndbuf < SOCKET_BUF_SIZE) {
        tcp_incoming_sndbuf = 0;
    }

    if (tcp_incoming_sndbuf != 0) {
        LOGI("set TCP incoming connection send buffer size to %d", tcp_incoming_sndbuf);
    }

    if (tcp_incoming_rcvbuf != 0 && tcp_incoming_rcvbuf < SOCKET_BUF_SIZE) {
        tcp_incoming_rcvbuf = 0;
    }

    if (tcp_incoming_rcvbuf != 0) {
        LOGI("set TCP incoming connection receive buffer size to %d", tcp_incoming_rcvbuf);
    }

    if (tcp_outgoing_sndbuf != 0 && tcp_outgoing_sndbuf < SOCKET_BUF_SIZE) {
        tcp_outgoing_sndbuf = 0;
    }

    if (tcp_outgoing_sndbuf != 0) {
        LOGI("set TCP outgoing connection send buffer size to %d", tcp_outgoing_sndbuf);
    }

    if (tcp_outgoing_rcvbuf != 0 && tcp_outgoing_rcvbuf < SOCKET_BUF_SIZE) {
        tcp_outgoing_rcvbuf = 0;
    }

    if (tcp_outgoing_rcvbuf != 0) {
        LOGI("set TCP outgoing connection receive buffer size to %d", tcp_outgoing_rcvbuf);
    }

    if (plugin != NULL) {
        int len          = 0;
        size_t buf_size  = 256 * remote_num;
        char *remote_str = ss_malloc(buf_size);

        snprintf(remote_str, buf_size, "%s", g_remote_addr[0].host);
        for (int i = 1; i < remote_num; i++) {
            snprintf(remote_str + len, buf_size - len, "|%s", g_remote_addr[i].host);
            len = strlen(remote_str);
        }
        int err = start_plugin(plugin, plugin_opts, remote_str,
                               remote_port, plugin_host, plugin_port, MODE_CLIENT);
        if (err) {
            FATAL("failed to start the plugin");
        }
    }

    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);

    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_init(&sigchld_watcher, signal_cb, SIGCHLD);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);
    ev_signal_start(EV_DEFAULT, &sigchld_watcher);

    // Setup keys
    LOGI("initializing ciphers... %s", method);
    crypto = crypto_init(password, key, method);
    if (crypto == NULL)
        FATAL("failed to initialize ciphers");

    // Setup proxy context
    struct listen_ctx listen_ctx;
    memset(&listen_ctx, 0, sizeof(struct listen_ctx));
    listen_ctx.remote_num  = remote_num;
    listen_ctx.remote_addr = ss_malloc(sizeof(struct sockaddr *) * remote_num);
    listen_ctx.remote_last_resolve_ts = ss_malloc(sizeof(uint64_t *) * remote_num);
    memset(listen_ctx.remote_addr, 0, sizeof(struct sockaddr *) * remote_num);
    memset(listen_ctx.remote_last_resolve_ts, 0, sizeof(uint64_t *) * remote_num);
    for (i = 0; i < remote_num; i++) {
        char *host = g_remote_addr[i].host;
        g_remote_addr[i].port = g_remote_addr[i].port == NULL ? remote_port : g_remote_addr[i].port;
        char *port = g_remote_addr[i].port;
        if (plugin != NULL) {
            host = plugin_host;
            port = plugin_port;
        }
        struct sockaddr_storage *storage = ss_malloc(sizeof(struct sockaddr_storage));
        memset(storage, 0, sizeof(struct sockaddr_storage));
        LOGI("resolving remote address...");
        if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
            FATAL("failed to resolve the provided hostname");
        }
        LOGI("remote address %d: %s", i, print_sockaddr(storage));
        listen_ctx.remote_addr[i] = (struct sockaddr *)storage;
        listen_ctx.remote_last_resolve_ts[i] = ss_malloc(sizeof(uint64_t));
        *listen_ctx.remote_last_resolve_ts[i] = millis();

        if (plugin != NULL)
            break;
    }
    listen_ctx.timeout = atoi(timeout);
    listen_ctx.mptcp   = mptcp;

    struct ev_loop *loop = EV_DEFAULT;

    strncpy(redir_port_str, local_port, sizeof(redir_port_str) - 1);

    listen_ctx_t *listen_ctx_current = &listen_ctx;
    do {
        if (listen_ctx_current->tos) {
            LOGI("listening at %s:%s (TOS 0x%x)", local_addr, local_port, listen_ctx_current->tos);
        } else {
            LOGI("listening at %s:%s", local_addr, local_port);
        }

        if (mode != UDP_ONLY) {
            // Setup socket
            int listenfd;
            listenfd = create_and_bind(local_addr, local_port);
            if (listenfd == -1) {
                FATAL("bind() error");
            }
            if (listen(listenfd, SOMAXCONN) == -1) {
                FATAL("listen() error");
            }
            setnonblocking(listenfd);

            listen_ctx_current->fd = listenfd;

            ev_io_init(&listen_ctx_current->io, accept_cb, listenfd, EV_READ);
            ev_io_start(loop, &listen_ctx_current->io);
        }

        // Setup UDP
        if (mode != TCP_ONLY) {
            LOGI("UDP relay enabled");
            char *host                       = g_remote_addr[0].host;
            char *port                       = g_remote_addr[0].port == NULL ? remote_port : g_remote_addr[0].port;
            struct sockaddr_storage *storage = ss_malloc(sizeof(struct sockaddr_storage));
            memset(storage, 0, sizeof(struct sockaddr_storage));
            if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
                FATAL("failed to resolve the provided hostname");
            }
            struct sockaddr *addr = (struct sockaddr *)storage;
            init_udprelay(local_addr, local_port, addr,
                          get_sockaddr_len(addr), mtu, crypto, listen_ctx_current->timeout, NULL);
        }

        if (mode == UDP_ONLY) {
            LOGI("TCP relay disabled");
        }

        // Handle additionals TOS/DSCP listening ports
        if (dscp_num > 0) {
            listen_ctx_current      = (listen_ctx_t *)ss_malloc(sizeof(listen_ctx_t));
            listen_ctx_current      = memcpy(listen_ctx_current, &listen_ctx, sizeof(listen_ctx_t));
            local_port              = dscp[dscp_num - 1].port;
            listen_ctx_current->tos = dscp[dscp_num - 1].dscp << 2;
        }
    } while (dscp_num-- > 0);

    // setuid
    if (user != NULL && !run_as(user)) {
        FATAL("failed to switch user");
    }

    if (geteuid() == 0) {
        LOGI("running from root user");
    }

    if (str_metric_port)
        metric_port = atoi(str_metric_port);

    if (str_metric_conntrack)
        metric_conntrack = atoi(str_metric_conntrack);

    if (str_metric_conncount)
        metric_conncount = atoi(str_metric_conncount);

    metrics_enabled = metric_port != 0 || prom_remote_enabled();

    if (metrics_enabled) {
        sem_init(&sem_prom_update, 0, 0);

        if (metric_port != 0)
            prom_init(&metrics, metric_port);

        prom_register(&metrics, &metric_ss_tx);
        prom_register(&metrics, &metric_ss_rx);
        prom_register(&metrics, &metric_ss_conn);

        if (metric_conntrack) {
            hash_tbl_init(&conn_tbl);
            prom_register(&metrics, &metric_conn_tx);
            prom_register(&metrics, &metric_conn_rx);

            if (metric_conncount)
                prom_register(&metrics, &metric_conn_cnt);
        }

        if (metric_port != 0) {
            if (pthread_create(&tid_prom_server, NULL, prom_server_worker, &should_stop))
                FATAL("failed to create prometheus thread");
        }

        if (pthread_create(&tid_prom_update, NULL, prom_update_worker, &should_stop))
            FATAL("failed to create prometheus thread");
    }

    ev_run(loop, 0);

    should_stop = 1;

    if (metrics_enabled) {
        sem_post(&sem_prom_update);
        if (metric_port != 0)
            pthread_cancel(tid_prom_server);
        pthread_join(tid_prom_update, NULL);

        if (metric_conntrack)
            conn_tbl_deinit(&conn_tbl);

        prom_cleanup(&metrics);
        sem_destroy(&sem_prom_update);
    }

    if (plugin != NULL) {
        stop_plugin();
    }

    for (i = 0; i < remote_num; i++)
        ss_free(listen_ctx.remote_addr[i]);
    ss_free(listen_ctx.remote_addr);
    ss_free(listen_ctx.remote_last_resolve_ts);

    return ret_val;
}
