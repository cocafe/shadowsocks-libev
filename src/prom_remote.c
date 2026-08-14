#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>

#include <snappy-c.h>

#include "prompb/types-v1.pb-c.h"
#include "prompb/remote-v1.pb-c.h"

#include "prom_remote.h"

static char prom_remote_addr[256];
static uint16_t prom_remote_port;
static char prom_remote_instance[64];

void
prom_remote_set_addr(const char *addr)
{
    snprintf(prom_remote_addr, sizeof(prom_remote_addr), "%s", addr ? addr : "");
}

void
prom_remote_set_port(uint16_t port)
{
    prom_remote_port = port;
}

void
prom_remote_set_instance(const char *instance)
{
    snprintf(prom_remote_instance, sizeof(prom_remote_instance), "%s", instance ? instance : "");
}

int
prom_remote_enabled(void)
{
    return prom_remote_addr[0] != '\0' && prom_remote_port != 0;
}

static int64_t
prom_remote_now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);

    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int
prom_remote_http_post(const char *host, uint16_t port, const void *body, size_t body_len)
{
    struct addrinfo hints;
    struct addrinfo *res, *rp;
    char port_str[8];
    char header[1024];
    struct timeval tv;
    int fd = -1;
    int n;
    size_t off;
    ssize_t r;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0)
        return -EINVAL;

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1)
            continue;

        tv.tv_sec  = 10;
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    if (fd == -1)
        return -EIO;

    n = snprintf(header, sizeof(header),
                 "POST /api/v1/write HTTP/1.1\r\n"
                 "Host: %s:%u\r\n"
                 "User-Agent: shadowsocks-libev\r\n"
                 "Content-Type: application/x-protobuf\r\n"
                 "Content-Encoding: snappy\r\n"
                 "X-Prometheus-Remote-Write-Version: 0.1.0\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n"
                 "\r\n",
                 host, (unsigned)port, body_len);
    if (n < 0 || (size_t)n >= sizeof(header)) {
        close(fd);
        return -EINVAL;
    }

    off = 0;
    while (off < (size_t)n) {
        r = send(fd, header + off, n - off, 0);
        if (r <= 0) {
            close(fd);
            return -EIO;
        }
        off += r;
    }

    off = 0;
    while (off < body_len) {
        r = send(fd, (const char *)body + off, body_len - off, 0);
        if (r <= 0) {
            close(fd);
            return -EIO;
        }
        off += r;
    }

    {
        char buf[512];

        do {
            r = recv(fd, buf, sizeof(buf), 0);
        } while (r > 0);
    }

    close(fd);

    return 0;
}

static int
prom_remote_build_body(prom_metric_set *s, uint8_t **out, size_t *out_len)
{
    Prometheus__WriteRequest req = PROMETHEUS__WRITE_REQUEST__INIT;
    Prometheus__TimeSeries **ts = NULL;
    Prometheus__Label **label_arrays = NULL;
    Prometheus__Sample **sample_arrays = NULL;
    uint8_t *packed = NULL;
    size_t n_metrics = 0;
    size_t idx = 0;
    size_t packed_len;
    int err = -ENOMEM;

    for (int i = 0; i < s->n_defs; i++) {
        prom_metric_def_set *ds = s->defs[i];
        prom_metric *m;

        list_for_each_entry(m, &ds->metrics, node) {
            n_metrics++;
        }
    }

    if (n_metrics == 0) {
        *out      = NULL;
        *out_len  = 0;
        return 0;
    }

    ts           = calloc(n_metrics, sizeof(*ts));
    label_arrays = calloc(n_metrics, sizeof(*label_arrays));
    sample_arrays = calloc(n_metrics, sizeof(*sample_arrays));
    if (!ts || !label_arrays || !sample_arrays)
        goto out;

    for (int i = 0; i < s->n_defs; i++) {
        prom_metric_def_set *ds = s->defs[i];
        prom_metric *m;

        list_for_each_entry(m, &ds->metrics, node) {
            Prometheus__TimeSeries *t;
            Prometheus__Label *labels;
            Prometheus__Label **label_ptrs;
            Prometheus__Sample *sample;
            Prometheus__Sample **sample_ptrs;
            size_t n_labels;
            size_t l = 0;

            n_labels = 1 + (prom_remote_instance[0] ? 1 : 0) + m->num_labels;

            t           = calloc(1, sizeof(*t));
            labels      = calloc(n_labels, sizeof(*labels));
            label_ptrs  = calloc(n_labels, sizeof(*label_ptrs));
            sample      = calloc(1, sizeof(*sample));
            sample_ptrs = calloc(1, sizeof(*sample_ptrs));

            if (!t || !labels || !label_ptrs || !sample || !sample_ptrs) {
                free(t);
                free(labels);
                free(label_ptrs);
                free(sample);
                free(sample_ptrs);
                goto out;
            }

            labels[l] = (Prometheus__Label)PROMETHEUS__LABEL__INIT;
            labels[l].name  = "__name__";
            labels[l].value = ds->def->name;
            label_ptrs[l]   = &labels[l];
            l++;

            if (prom_remote_instance[0]) {
                labels[l] = (Prometheus__Label)PROMETHEUS__LABEL__INIT;
                labels[l].name  = "instance";
                labels[l].value = prom_remote_instance;
                label_ptrs[l]   = &labels[l];
                l++;
            }

            for (int k = 0; k < m->num_labels; k++, l++) {
                labels[l] = (Prometheus__Label)PROMETHEUS__LABEL__INIT;
                labels[l].name  = m->labels[k].key;
                labels[l].value = m->labels[k].value;
                label_ptrs[l]   = &labels[l];
            }

            *sample = (Prometheus__Sample)PROMETHEUS__SAMPLE__INIT;
            sample->has_value     = 1;
            sample->value         = m->value;
            sample->has_timestamp = 1;
            sample->timestamp     = prom_remote_now_ms();
            sample_ptrs[0]        = sample;

            *t          = (Prometheus__TimeSeries)PROMETHEUS__TIME_SERIES__INIT;
            t->n_labels = l;
            t->labels   = label_ptrs;
            t->n_samples = 1;
            t->samples  = sample_ptrs;

            ts[idx]            = t;
            label_arrays[idx]  = labels;
            sample_arrays[idx] = sample;
            idx++;
        }
    }

    req.n_timeseries = idx;
    req.timeseries   = ts;

    packed_len = prometheus__write_request__get_packed_size(&req);
    packed     = malloc(packed_len);
    if (!packed)
        goto out;

    prometheus__write_request__pack(&req, packed);

    *out     = packed;
    *out_len = packed_len;
    packed   = NULL;
    err      = 0;

out:
    if (ts) {
        for (size_t k = 0; k < idx; k++) {
            Prometheus__TimeSeries *t = ts[k];

            if (t) {
                if (t->labels)
                    free(t->labels);
                if (t->samples)
                    free(t->samples);
                free(t);
            }

            if (label_arrays && label_arrays[k])
                free(label_arrays[k]);
            if (sample_arrays && sample_arrays[k])
                free(sample_arrays[k]);
        }

        free(ts);
    }

    if (label_arrays)
        free(label_arrays);
    if (sample_arrays)
        free(sample_arrays);
    if (packed)
        free(packed);

    return err;
}

int
prom_remote_write(prom_metric_set *s)
{
    uint8_t *body = NULL;
    uint8_t *comp = NULL;
    size_t body_len = 0;
    size_t comp_max;
    size_t comp_len;
    int err;

    if (!prom_remote_enabled())
        return -EINVAL;

    err = prom_remote_build_body(s, &body, &body_len);
    if (err)
        return err;

    if (body_len == 0)
        return 0;

    comp_max = snappy_max_compressed_length(body_len);
    comp     = malloc(comp_max);
    if (!comp) {
        free(body);
        return -ENOMEM;
    }

    comp_len = comp_max;
    err      = snappy_compress((const char *)body, body_len, (char *)comp, &comp_len);
    free(body);

    if (err != SNAPPY_OK) {
        free(comp);
        return -EIO;
    }

    err = prom_remote_http_post(prom_remote_addr, prom_remote_port, comp, comp_len);
    free(comp);

    return err;
}
