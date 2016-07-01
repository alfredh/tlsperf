/**
 * @file endpoint.c TLS Endpoint code (Client or Server)
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <re.h>
#include "tlsperf.h"


struct tls_endpoint {
	struct tls *tls;
	struct tcp_sock *ts;
	struct tcp_conn *tc;
	struct tls_conn *sc;
	struct dtls_sock *ds;
	struct sa addr;
	int proto;
	bool verbose;
	bool client;
	bool established;
	tls_endpoint_estab_h *estabh;
	tls_endpoint_error_h *errorh;
	void *arg;
};


static void destructor(void *arg)
{
	struct tls_endpoint *ep = arg;

	mem_deref(ep->sc);
	mem_deref(ep->tc);
	mem_deref(ep->ts);
	mem_deref(ep->ds);
	mem_deref(ep->tls);
}


static void conn_close(struct tls_endpoint *ep, int err)
{
	ep->sc = mem_deref(ep->sc);
	ep->tc = mem_deref(ep->tc);

	ep->errorh(err, ep->arg);
}


static void tcp_estab_handler(void *arg)
{
	struct tls_endpoint *ep = arg;

	if (ep->verbose) {
		re_printf("[ %s ] TLS established, cipher is %s\n",
			  ep->client ? "Client" : "Server",
			  tls_cipher_name(ep->sc));
	}

	ep->established = true;

	ep->estabh(tls_cipher_name(ep->sc), ep->arg);
}


static void tcp_close_handler(int err, void *arg)
{
	struct tls_endpoint *ep = arg;

	conn_close(ep, err);
}


static void tcp_conn_handler(const struct sa *peer, void *arg)
{
	struct tls_endpoint *ep = arg;
	int err;
	(void)peer;

	err = tcp_accept(&ep->tc, ep->ts, tcp_estab_handler,
			 0, tcp_close_handler, ep);

	if (err) {
		conn_close(ep, err);
		return;
	}

	err = tls_start_tcp(&ep->sc, ep->tls, ep->tc, 0);
	if (err) {
		conn_close(ep, err);
		return;
	}
}


static void dtls_estab_handler(void *arg)
{
	struct tls_endpoint *ep = arg;

	if (ep->verbose) {
		re_printf("[ %s ] DTLS established, cipher is %s\n",
			  ep->client ? "Client" : "Server",
			  tls_cipher_name(ep->sc));
	}

	ep->established = true;

	ep->estabh(tls_cipher_name(ep->sc), ep->arg);
}


static void dtls_close_handler(int err, void *arg)
{
	struct tls_endpoint *ep = arg;

	conn_close(ep, err);
}


static void dtls_conn_handler(const struct sa *peer, void *arg)
{
	struct tls_endpoint *ep = arg;
	int err;
	(void)peer;

	if (ep->client || ep->sc) {
		conn_close(ep, EPROTO);
		return;
	}

	err = dtls_accept(&ep->sc, ep->tls, ep->ds, dtls_estab_handler,
			  NULL, dtls_close_handler, ep);
	if (err) {
		conn_close(ep, err);
	}
}


int tls_endpoint_alloc(struct tls_endpoint **epp, struct tls *tls,
		       bool verbose, bool client, int proto,
		       tls_endpoint_estab_h *estabh,
		       tls_endpoint_error_h *errorh, void *arg)
{
	struct tls_endpoint *ep;
	int err = 0;

	ep = mem_zalloc(sizeof(*ep), destructor);
	if (!ep)
		return ENOMEM;

	ep->tls = mem_ref(tls);
	ep->verbose = verbose;
	ep->client = client;
	ep->proto = proto;
	ep->estabh = estabh;
	ep->errorh = errorh;
	ep->arg = arg;

	sa_set_str(&ep->addr, "127.0.0.1", 0);

	switch (proto) {

	case IPPROTO_TCP:
		if (!client) {
			err = tcp_listen(&ep->ts, &ep->addr,
					 tcp_conn_handler, ep);
			if (err)
				goto out;

			err = tcp_sock_local_get(ep->ts, &ep->addr);
			if (err)
				goto out;
		}
		break;

	case IPPROTO_UDP:
		err = dtls_listen(&ep->ds, &ep->addr, NULL, 1, 0,
				  dtls_conn_handler, ep);
		if (err) {
			re_fprintf(stderr, "dtls_listen failed (%m)\n", err);
			goto out;
		}

		err = udp_local_get(dtls_udp_sock(ep->ds), &ep->addr);
		if (err)
			goto out;
		break;

	default:
		err = EPROTONOSUPPORT;
		break;
	}
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(ep);
	else if (epp)
		*epp = ep;

	return err;
}


int tls_endpoint_start(struct tls_endpoint *ep, const struct sa *addr)
{
	int err;

	if (!ep)
		return EINVAL;

	if (!ep->client)
		return EPROTO;

	switch (ep->proto) {

	case IPPROTO_TCP:
		err = tcp_connect(&ep->tc, addr, tcp_estab_handler, NULL,
				  tcp_close_handler, ep);
		if (err)
			return err;

		err = tls_start_tcp(&ep->sc, ep->tls, ep->tc, 0);
		if (err)
			return err;
		break;

	case IPPROTO_UDP:
		err = dtls_connect(&ep->sc, ep->tls, ep->ds, addr,
				   dtls_estab_handler, NULL,
				   dtls_close_handler, ep);
		if (err) {
			re_fprintf(stderr, "dtls_connect failed (%m)\n", err);
			return err;
		}
		break;

	default:
		return EPROTONOSUPPORT;
	}

	return 0;
}


const struct sa *tls_endpoint_addr(const struct tls_endpoint *ep)
{
	return ep ? &ep->addr : NULL;
}


bool tls_endpoint_established(const struct tls_endpoint *ep)
{
	return ep ? ep->established : false;
}
