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

struct test_params {
	bool tflag;
	bool nflag;
	int tvalue;
	int nvalue;
};

const char usage_str[] = "Usage: %s [OPTION]... <cipher>|<hash>\n"
	"Run benchmark test for cipher or hash\n\n"
	"  -t <secs>\t" "time to run each test (default 10 secs)\n"
	"  -n <bytes>\t" "size of the test buffer\n"
	"  -h\t\t" "show this help\n"
;

int run_null(int fdc, struct test_params tp);
int run_aes_128_cbc(int fdc, struct test_params tp);
int run_aes_256_xts(int fdc, struct test_params tp);
int run_crc32c(int fdc, struct test_params tp);
int run_sha1(int fdc, struct test_params tp);
int run_sha256(int fdc, struct test_params tp);
int get_alignmask(int fdc, struct session_op *sess);

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

static volatile int must_finish;
static volatile int must_exit;

static void alarm_handler(int signo)
{
        must_finish = 1;
}

static void exit_handler(int signo)
{
	must_exit = 1;
	printf("\nexit requested by user through ctrl+c \n");
}

static char *units[] = { "", "Ki", "Mi", "Gi", "Ti", 0};

static void value2human(double bytes, double time, double* data, double* speed,char* metric)
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

static int encrypt_data(int fdc, struct test_params tp, struct session_op *sess)
{
	struct crypt_op cop;
	char *buffer, iv[32];
	char mac[HASH_MAX_LEN];
	static int val = 23;
	struct timeval start, end;
	double total = 0;
	double secs, ddata, dspeed;
	char metric[16];
	int alignmask;
	int min_alignmask = sizeof(void*) - 1;

	memset(iv, 0x23, 32);

	printf("\tEncrypting in chunks of %d bytes: ", tp.nvalue);
	fflush(stdout);

	alignmask = get_alignmask(fdc, sess);
	if (alignmask) {
		alignmask = ((alignmask < min_alignmask) ? min_alignmask : alignmask);
		if (posix_memalign((void **)(&buffer), alignmask + 1, tp.nvalue)) {
			printf("posix_memalign() failed!\n");
			return 1;
		}
	} else {
		if (!(buffer = malloc(tp.nvalue))) {
			perror("malloc()");
			return 1;
		}
	}
	memset(buffer, val++, tp.nvalue);
	
	must_finish = 0;
	alarm(tp.tvalue);

	gettimeofday(&start, NULL);
	do {
		memset(&cop, 0, sizeof(cop));
		cop.ses = sess->ses;
		cop.len = tp.nvalue;
		cop.iv = (unsigned char *)iv;
		cop.op = COP_ENCRYPT;
		cop.src = cop.dst = (unsigned char *)buffer;
		cop.mac = (unsigned char *)mac;

		if (ioctl(fdc, CIOCCRYPT, &cop)) {
			perror("ioctl(CIOCCRYPT)");
			return 1;
		}
		total += cop.len;
	} while(!must_finish);
	gettimeofday(&end, NULL);

	secs = udifftimeval(start, end)/ 1000000.0;

	value2human(total, secs, &ddata, &dspeed, metric);
	printf ("done. %.2f %s in %.2f secs: ", ddata, metric, secs);
	printf ("%.2f %s/sec\n", dspeed, metric);

	free(buffer);
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

	ciphers[id].func(fdc, tp);

	close(fdc);
	close(fd);

	return 0;
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
			if (must_exit)
				break;

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

	fprintf(stderr, "\nTesting AES-128-CBC cipher: \n");
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

	fprintf(stderr, "\nTesting AES-256-XTS cipher: \n");
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

	fprintf(stderr, "\nTesting CRC32C hash: \n");
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

	fprintf(stderr, "\nTesting SHA-1 hash: \n");
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

	fprintf(stderr, "\nTesting SHA2-256 hash: \n");
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
	bool alg_flag;
	char *alg_name;
	struct test_params tp;

	tp.tflag = false;
	tp.nflag = false;
	alg_flag = false;
	opterr = 0;
	while ((c = getopt(argc, argv, "hn:t:")) != -1) {
		switch (c) {
		case 'n':
			tp.nvalue = atoi(optarg);
			tp.nflag = true;
			break;
		case 't':
			tp.tvalue = atoi(optarg);
			tp.tflag = true;
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
	signal(SIGINT, exit_handler);

	for (i = 0; i < ALG_COUNT; i++) {
		if (must_exit)
			break;

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
