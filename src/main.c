/**
 * @file main.c Main application code
 *
 * Copyright (C) 2010 Alfred E. Heggestad
 */

#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <openssl/crypto.h>
#include <re.h>
#include "tlsperf.h"


#define DEBUG_MODULE "tlsperf"
#define DEBUG_LEVEL 6
#include <re_dbg.h>


static struct {
	struct tls *tls;

	struct tls_endpoint *ep_cli;
	struct tls_endpoint *ep_srv;

	unsigned num;
	unsigned count;

	uint64_t ts_start;
	uint64_t ts_estab;

	bool verbose;
	int proto;
	int err;
} tlsperf;


static int  start_test(void);
static void stop_test(void);


static void print_report(void)
{
	int dur;

	dur = (int)(tlsperf.ts_estab - tlsperf.ts_start);

	re_printf("~~~ Summary: ~~~\n");
	re_printf("num_connections:      %u\n", tlsperf.num);
	re_printf("total_duration:       %d ms\n", dur);
	re_printf("avg_time_per_conn:    %.3f ms\n",
		  1.0 * dur / tlsperf.num);
	re_printf("connections_per_sec:  %.3f\n",
		  1000.0 * tlsperf.num / (1.0 * dur));
	re_printf("\n");
}


static void abort_test(int err)
{
	tlsperf.err = err;
	re_cancel();
}


static void tls_endpoint_estab_handler(const char *cipher, void *arg)
{
	int err;
	(void)arg;

	re_fprintf(stderr, "\r[ %u .. %c ]",
		   tlsperf.count,
		   0x20 + tlsperf.count % 0x60);

	if (tls_endpoint_established(tlsperf.ep_cli) &&
	    tls_endpoint_established(tlsperf.ep_srv)) {

		if (tlsperf.count >= tlsperf.num) {

			tlsperf.ts_estab = tmr_jiffies();

			re_printf("\nDONE!\n");
			re_printf("cipher:        %s\n", cipher);
			print_report();

			re_cancel();
		}
		else {
			stop_test();
			err = start_test();
			if (err)
				abort_test(err);
		}
	}
}


static void tls_endpoint_error_handler(int err, void *arg)
{
	(void)arg;

	re_fprintf(stderr, "TLS Endpoint error (%m) -- ABORT\n", err);

	abort_test(err);
}


static int start_test(void)
{
	int err;

	tlsperf.count++;

	err = tls_endpoint_alloc(&tlsperf.ep_cli, tlsperf.tls,
				 tlsperf.verbose, true, tlsperf.proto,
				 tls_endpoint_estab_handler,
				 tls_endpoint_error_handler, NULL);
	if (err)
		return err;

	err = tls_endpoint_alloc(&tlsperf.ep_srv, tlsperf.tls,
				 tlsperf.verbose, false, tlsperf.proto,
				 tls_endpoint_estab_handler,
				 tls_endpoint_error_handler, NULL);
	if (err)
		return err;

	err = tls_endpoint_start(tlsperf.ep_cli,
				 tls_endpoint_addr(tlsperf.ep_srv));
	if (err)
		return err;

	return 0;
}


static void stop_test(void)
{
	tlsperf.ep_srv = mem_deref(tlsperf.ep_srv);
	tlsperf.ep_cli = mem_deref(tlsperf.ep_cli);
}


static void usage(void)
{
	(void)re_fprintf(stderr,
			 "tlsperf -h\n"
			 "\n"
			 "\t-c <PEM>    Use this certificate file\n"
			 "\t-d          Use DTLS protocol\n"
			 "\t-n <NUM>    Number of TLS connections\n"
			 "\n"
			 "\t-h          Show summary of options\n"
			 "\t-v          Verbose output\n"
			 );
}


int main(int argc, char *argv[])
{
	const char *cert = NULL;
	int err = 0;

	tlsperf.num = 1;
	tlsperf.proto = IPPROTO_TCP;

	for (;;) {

		const int c = getopt(argc, argv, "a:dc:e:p:n:s:hv");
		if (0 > c)
			break;

		switch (c) {

		case 'c':
			cert = optarg;
			break;

		case 'd':
			tlsperf.proto = IPPROTO_UDP;
			break;

		case 'n':
			tlsperf.num = atoi(optarg);
			break;

		case 'v':
			tlsperf.verbose = true;
			break;

		case '?':
			err = EINVAL;
			/*@fallthrough@*/
		case 'h':
			usage();
			return err;
		}
	}

	err = libre_init();
	if (err)
		goto out;

	re_printf("tlsperf -- TLS performance testing program\n");
	re_printf("build:         %H\n", sys_build_get, 0);
	re_printf("compiler:      %s\n", __VERSION__);
	re_printf("libre:         %s\n", sys_libre_version_get());
	re_printf("os:            %s\n", sys_os_get());
	re_printf("arch:          %s\n", sys_arch_get());

#ifdef USE_OPENSSL
	re_printf("openssl info:  %s\n%s\n",
		  SSLeay_version(SSLEAY_VERSION),
		  SSLeay_version(SSLEAY_CFLAGS));
#endif

	re_printf("protocol:      %s\n",
		  tlsperf.proto == IPPROTO_TCP ? "TLS" : "DTLS");

	err = tls_alloc(&tlsperf.tls, TLS_METHOD_SSLV23, cert, 0);
	if (err)
		goto out;

	if (cert) {
		re_printf("certificate:   %s\n", cert);
	}
	else {
		re_printf("certificate:   selfsigned RSA-1024\n");
		err = tls_set_selfsigned(tlsperf.tls, "a@b");
		if (err) {
			re_printf("failed to set self-signed certificate (%m)\n", err);
			goto out;
		}
	}

	re_printf("starting tests now. (num=%u)\n", tlsperf.num);

	/*
	 * Start timing now
	 */

	tlsperf.ts_start = tmr_jiffies();

	err = start_test();
	if (err)
		goto out;

	re_main(0);

 out:
	if (err) {
		re_printf("program failed with error: %m\n", err);
	}

	mem_deref(tlsperf.ep_srv);
	mem_deref(tlsperf.ep_cli);

	mem_deref(tlsperf.tls);

	libre_close();

	/* check for memory leaks */
	mem_debug();
	tmr_debug();

	return err ? err : tlsperf.err;
}
