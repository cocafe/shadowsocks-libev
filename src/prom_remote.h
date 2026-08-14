#ifndef PROM_REMOTE_H
#define PROM_REMOTE_H

#include <stdint.h>

#include "prometheus.h"

void prom_remote_set_addr(const char *addr);
void prom_remote_set_port(uint16_t port);
void prom_remote_set_instance(const char *instance);

int prom_remote_enabled(void);
int prom_remote_write(prom_metric_set *s);

#endif // PROM_REMOTE_H
