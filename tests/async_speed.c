/*  cryptodev_test - simple benchmark tool for cryptodev
 *
 *    Copyright (C) 2010 by Phil Sutter <phil.sutter@viprinet.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <crypto/cryptodev.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>

#ifdef ENABLE_ASYNC

struct test_params {
	bool tflag;
	bool nflag;
	bool mflag;
	int tvalue;
	int nvalue;
};

const char usage_str[] = "Usage: %s [OPTION]... <cipher>|<hash>\n"
	"Run benchmark test for cipher or hash\n\n"
	"  -t <secs>\t" "time to run each test (default 10 secs)\n"
	"  -n <bytes>\t" "size of the test buffer\n"
	"  -m\t\t" "output in a machine readable format\n"
	"  -h\t\t" "show this help\n"
;

int run_null(int fdc, struct test_params tp);
int run_aes_128_cbc(int fdc, struct test_params tp);
int run_aes_256_xts(int fdc, struct test_params tp);
int run_crc32c(int fdc, struct test_params tp);
int run_sha1(int fdc, struct test_params tp);
int run_sha256(int fdc, struct test_params tp);

#define ALG_COUNT	6
struct {
	char *name;
	int (*func)(int, struct test_params);
} ciphers[ALG_COUNT] = {
	{"null",	run_null},
	{"aes-128-cbc",	run_aes_128_cbc},
	{"aes-256-xts",	run_aes_256_xts},
	{"crc32c",	run_crc32c},
	{"sha1",	run_sha1},
	{"sha256",	run_sha256},
};

static double udifftimeval(struct timeval start, struct timeval end)
{
	return (double)(end.tv_usec - start.tv_usec) +
	       (double)(end.tv_sec - start.tv_sec) * 1000 * 1000;
}

static int must_finish = 0;
static struct pollfd pfd;

static void alarm_handler(int signo)
{
        must_finish = 1;
	pfd.events = POLLIN;
}

static char *units[] = { "", "Ki", "Mi", "Gi", "Ti", 0};

static void value2human(uint64_t bytes, double time, double* data, double* speed,char* metric)
{
	int unit = 0;

	*data = bytes;
	while (*data > 1024 && units[unit + 1]) {
		*data /= 1024;
		unit++;
	}
	*speed = *data / time;
	sprintf(metric, "%sB", units[unit]);
}

static void value2machine(uint64_t bytes, double time, double* speed)
{
	*speed = bytes / time;
}


int encrypt_data(int fdc, struct test_params tp, struct session_op *sess)
{
	struct crypt_op cop;
	char *buffer[64], iv[32];
	char mac[64][HASH_MAX_LEN];
	static int val = 23;
	struct timeval start, end;
	uint64_t total = 0;
	double secs, ddata, dspeed;
	char metric[16];
	int rc, wqueue = 0, bufidx = 0;
	int alignmask;

	memset(iv, 0x23, 32);

	if (!tp.mflag) {
		printf("\tBuffer size %d bytes: ", tp.nvalue);
		fflush(stdout);
	}

	alignmask = get_alignmask(fdc, sess);
	for (rc = 0; rc < 64; rc++) {
		if (alignmask) {
			if (posix_memalign((void **)(buffer + rc), alignmask + 1, tp.nvalue)) {
				printf("posix_memalign() failed!\n");
				return 1;
			}
		} else {
			if (!(buffer[rc] = malloc(tp.nvalue))) {
				perror("malloc()");
				return 1;
			}
		}
		memset(buffer[rc], val++, tp.nvalue);
	}
	pfd.fd = fdc;
	pfd.events = POLLOUT | POLLIN;

	must_finish = 0;
	alarm(tp.tvalue);

	gettimeofday(&start, NULL);
	do {
		if ((rc = poll(&pfd, 1, 100)) < 0) {
			if (errno & (ERESTART | EINTR))
				continue;
			fprintf(stderr, "errno = %d ", errno);
			perror("poll()");
			return 1;
		}

		if (pfd.revents & POLLOUT) {
			memset(&cop, 0, sizeof(cop));
			cop.ses = sess->ses;
			cop.len = tp.nvalue;
			cop.iv = (unsigned char *)iv;
			cop.op = COP_ENCRYPT;
			cop.src = cop.dst = (unsigned char *)buffer[bufidx];
			cop.mac = mac[bufidx];
			bufidx = (bufidx + 1) % 64;

			if (ioctl(fdc, CIOCASYNCCRYPT, &cop)) {
				perror("ioctl(CIOCASYNCCRYPT)");
				return 1;
			}
			wqueue++;
		}
		if (pfd.revents & POLLIN) {
			if (ioctl(fdc, CIOCASYNCFETCH, &cop)) {
				perror("ioctl(CIOCASYNCFETCH)");
				return 1;
			}
			wqueue--;
			total += cop.len;
		}
	} while(!must_finish || wqueue);
	gettimeofday(&end, NULL);

	secs = udifftimeval(start, end)/ 1000000.0;

	if (tp.mflag) {
		value2machine(total, secs, &dspeed);
		printf("%" PRIu64 "\t%.2f\t%.2f\n", total, secs, dspeed);
	} else {
		value2human(total, secs, &ddata, &dspeed, metric);
		printf ("done. %.2f %s in %.2f secs: ", ddata, metric, secs);
		printf ("%.2f %s/sec\n", dspeed, metric);
	}

	for (rc = 0; rc < 64; rc++)
		free(buffer[rc]);
	return 0;
}

void usage(char *cmd_name)
{
	printf(usage_str, cmd_name);
}

int run_test(int id, struct test_params tp)
{
	int fd;
	int fdc;

	fd = open("/dev/crypto", O_RDWR, 0);
	if (fd < 0) {
		perror("open()");
		return fd;
	}
	if (ioctl(fd, CRIOGET, &fdc)) {
		perror("ioctl(CRIOGET)");
		return -EINVAL;
	}

	if (!tp.mflag) {
		fprintf(stderr, "Testing %s:\n", ciphers[id].name);
	}
	ciphers[id].func(fdc, tp);

	close(fdc);
	close(fd);
}

int get_alignmask(int fdc, struct session_op *sess)
{
	int alignmask;

#ifdef CIOCGSESSINFO
	struct session_info_op siop;

	siop.ses = sess->ses;
	if (ioctl(fdc, CIOCGSESSINFO, &siop)) {
		perror("ioctl(CIOCGSESSINFO)");
		return -EINVAL;
	}
	alignmask = siop.alignmask;
#else
	alignmask = 0;
#endif

	return alignmask;
}

void do_test_vectors(int fdc, struct test_params tp, struct session_op *sess)
{
	int i;

	if (tp.nflag) {
		encrypt_data(fdc, tp, sess);
	} else {
		for (i = 256; i <= (64 * 1024); i *= 2) {
			tp.nvalue = i;
			if (encrypt_data(fdc, tp, sess)) {
				break;
			}
		}
	}
}


int run_null(int fdc, struct test_params tp)
{
	struct session_op sess;
	char keybuf[32];
	int alignmask;
	int i;

	fprintf(stderr, "Testing NULL cipher: \n");
	memset(&sess, 0, sizeof(sess));
	sess.cipher = CRYPTO_NULL;
	sess.keylen = 0;
	sess.key = (unsigned char *)keybuf;
	if (ioctl(fdc, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return -EINVAL;
	}

	do_test_vectors(fdc, tp, &sess);
	return 0;
}

int run_aes_128_cbc(int fdc, struct test_params tp)
{
	struct session_op sess;
	char keybuf[32];
	int alignmask;
	int i;

	memset(&sess, 0, sizeof(sess));
	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = 16;
	memset(keybuf, 0x42, 16);
	sess.key = (unsigned char *)keybuf;
	if (ioctl(fdc, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return -EINVAL;
	}

	do_test_vectors(fdc, tp, &sess);
	return 0;
}

int run_aes_256_xts(int fdc, struct test_params tp)
{
	struct session_op sess;
	char keybuf[32];

	memset(&sess, 0, sizeof(sess));
	sess.cipher = CRYPTO_AES_XTS;
	sess.keylen = 32;
	memset(keybuf, 0x42, sess.keylen);
	sess.key = (unsigned char *)keybuf;
	if (ioctl(fdc, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return -EINVAL;
	}

	do_test_vectors(fdc, tp, &sess);
	return 0;
}

int run_crc32c(int fdc, struct test_params tp)
{
	struct session_op sess;

	memset(&sess, 0, sizeof(sess));
	sess.mac = CRYPTO_CRC32C;
	if (ioctl(fdc, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return 1;
	}

	do_test_vectors(fdc, tp, &sess);
	return 0;
}

int run_sha1(int fdc, struct test_params tp)
{
	struct session_op sess;

	memset(&sess, 0, sizeof(sess));
	sess.mac = CRYPTO_SHA1;
	if (ioctl(fdc, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return 1;
	}

	do_test_vectors(fdc, tp, &sess);
	return 0;
}

int run_sha256(int fdc, struct test_params tp)
{
	struct session_op sess;

	memset(&sess, 0, sizeof(sess));
	sess.mac = CRYPTO_SHA2_256;
	if (ioctl(fdc, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return 1;
	}

	do_test_vectors(fdc, tp, &sess);
	return 0;
}

int main(int argc, char **argv)
{
	int i;
	int c;
	int index;
	bool alg_flag;
	char *alg_name;
	struct test_params tp;

	tp.tflag = false;
	tp.nflag = false;
	tp.mflag = false;
	alg_flag = false;
	opterr = 0;
	while ((c = getopt(argc, argv, "hn:t:m")) != -1) {
		switch (c) {
		case 'n':
			tp.nvalue = atoi(optarg);
			tp.nflag = true;
			break;
		case 't':
			tp.tvalue = atoi(optarg);
			tp.tflag = true;
			break;
		case 'm':
			tp.mflag = true;
			break;
		case 'h': /* no break */
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	/* the name of a specific test asked on the command line */
	if (optind < argc) {
		alg_name = argv[optind];
		alg_flag = true;
	}

	/* default test time */
	if (!tp.tflag) {
		tp.tvalue = 5;
	}

	signal(SIGALRM, alarm_handler);

	for (i = 0; i < ALG_COUNT; i++) {
		if (alg_flag) {
			if (strcmp(alg_name, ciphers[i].name) == 0) {
				run_test(i, tp);
			}
		} else {
			run_test(i, tp);
		}
	}

	return 0;
}

#else
int
main(int argc, char** argv)
{
	return (0);
}
#endif
