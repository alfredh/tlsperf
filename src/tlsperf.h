/**
 * @file tlsperf.h Internal api
 *
 * Copyright (C) 2010 - 2016 Alfred E. Heggestad
 */


struct tls_endpoint;


typedef void (tls_endpoint_estab_h)(const char *cipher, void *arg);
typedef void (tls_endpoint_error_h)(int err, void *arg);


int tls_endpoint_alloc(struct tls_endpoint **epp, struct tls *tls,
		       bool verbose, bool client, int proto,
		       tls_endpoint_estab_h *estabh,
		       tls_endpoint_error_h *errorh, void *arg);
int tls_endpoint_start(struct tls_endpoint *ep, const struct sa *addr);
const struct sa *tls_endpoint_addr(const struct tls_endpoint *ep);
bool tls_endpoint_established(const struct tls_endpoint *ep);


uint64_t tmr_microseconds(void);
