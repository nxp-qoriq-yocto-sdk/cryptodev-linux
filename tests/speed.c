/*  cryptodev_test - simple benchmark tool for cryptodev
 *
 *    Copyright (C) 2010 by Phil Sutter <phil.sutter@viprinet.com>
 *    Copyright 2016-2017 NXP
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
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <crypto/cryptodev.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>

#define AUTH_SIZE 	31
#define TAG_LEN		20

struct test_params {
	bool tflag;
	bool nflag;
	bool mflag;
	bool aflag;
	bool authflag;
	int tvalue;
	int nvalue;
};

const char usage_str[] = "Usage: %s [OPTION]... <cipher>|<hash>\n"
	"Run benchmark test for cipher or hash\n\n"
	"  -t <secs>\t" "time to run each test (default 10 secs)\n"
	"  -n <bytes>\t" "size of the test buffer\n"
	"  -m\t\t" "output in a machine readable format\n"
	"  -a\t\t" "run the async tests (default sync)\n"
	"  -h\t\t" "show this help\n\n"
	"Note: SEC driver is configured to support buffers smaller than 512K\n"
;

int run_null(int fdc, struct test_params tp);
int run_aes_128_cbc(int fdc, struct test_params tp);
int run_aes_256_xts(int fdc, struct test_params tp);
int run_crc32c(int fdc, struct test_params tp);
int run_sha1(int fdc, struct test_params tp);
int run_sha256(int fdc, struct test_params tp);
int run_authenc(int fdc, struct test_params tp);
int run_rsa(int fdc, struct test_params tp);

#define ALG_COUNT	8
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
	{"authenc", 	run_authenc},
	{"rsa",		run_rsa},
};

static double udifftimeval(struct timeval start, struct timeval end)
{
	return (double)(end.tv_usec - start.tv_usec) +
	       (double)(end.tv_sec - start.tv_sec) * 1000 * 1000;
}

static volatile int must_finish;
static volatile int must_exit;
static struct pollfd pfd;

static void alarm_handler(int signo)
{
        must_finish = 1;
	pfd.events = POLLIN;
}

static void exit_handler(int signo)
{
	must_exit = 1;
	printf("\nexit requested by user through ctrl+c \n");
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

int get_alignmask(int fdc, struct session_op *sess)
{
	int alignmask;
	int min_alignmask = sizeof(void*) - 1;

#ifdef CIOCGSESSINFO
	struct session_info_op siop;

	siop.ses = sess->ses;
	if (ioctl(fdc, CIOCGSESSINFO, &siop)) {
		perror("ioctl(CIOCGSESSINFO)");
		return -EINVAL;
	}
	alignmask = siop.alignmask;
	if (alignmask < min_alignmask) {
		alignmask = min_alignmask;
	}
#else
	alignmask = 0;
#endif

	return alignmask;
}

int encrypt_async(int fdc, struct test_params tp, struct session_op *sess)
{
	struct crypt_op cop;
	char *buffer[64], iv[32];
	uint8_t mac[64][HASH_MAX_LEN];
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


static int encrypt_sync(int fdc, struct test_params tp, struct session_op *sess)
{
	struct crypt_op cop;
	char *buffer, iv[32];
	char mac[HASH_MAX_LEN];
	static int val = 23;
	struct timeval start, end;
	uint64_t total = 0;
	double secs, ddata, dspeed;
	char metric[16];
	int alignmask;
	int min_alignmask = sizeof(void*) - 1;

	memset(iv, 0x23, 32);

	if (!tp.mflag) {
		printf("\tBuffer size %d bytes: ", tp.nvalue);
		fflush(stdout);
	}

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

	if (tp.mflag) {
		value2machine(total, secs, &dspeed);
		printf("%" PRIu64 "\t%.2f\t%.2f\n", total, secs, dspeed);
	} else {
		value2human(total, secs, &ddata, &dspeed, metric);
		printf ("done. %.2f %s in %.2f secs: ", ddata, metric, secs);
		printf ("%.2f %s/sec\n", dspeed, metric);
	}

	free(buffer);
	return 0;
}

static int encrypt_auth(int fdc, struct test_params tp, struct session_op *sess)
{
	struct crypt_auth_op cao;
	char *buffer, iv[32];
	uint8_t auth[AUTH_SIZE];
	static int val = 23;
	struct timeval start, end;
	uint64_t total = 0;
	double secs, ddata, dspeed;
	char metric[16];
	int alignmask;
	int min_alignmask = sizeof(void*) - 1;
	int alloc_size;

	memset(iv, 0x23, 32);
	memset(auth, 0xf1, sizeof(auth));

	if (!tp.mflag) {
		printf("\tBuffer size %d bytes: ", tp.nvalue);
		fflush(stdout);
	}

	alloc_size = tp.nvalue + TAG_LEN;
	alignmask = get_alignmask(fdc, sess);
	if (alignmask) {
		alignmask = ((alignmask < min_alignmask) ? min_alignmask : alignmask);
		if (posix_memalign((void **)(&buffer), alignmask + 1, alloc_size)) {
			printf("posix_memalign() failed!\n");
			return 1;
		}
	} else {
		if (!(buffer = malloc(alloc_size))) {
			perror("malloc()");
			return 1;
		}
	}
	memset(buffer, val++, tp.nvalue);

	must_finish = 0;
	alarm(tp.tvalue);

	gettimeofday(&start, NULL);
	do {
		memset(&cao, 0, sizeof(cao));
		cao.ses = sess->ses;
		cao.auth_src = auth;
		cao.auth_len = sizeof(auth);
		cao.len = tp.nvalue;
		cao.iv = (unsigned char *)iv;
		cao.op = COP_ENCRYPT;
		cao.src = (unsigned char *)buffer;
		cao.dst = cao.src;
		cao.tag_len = TAG_LEN;
		cao.flags = COP_FLAG_AEAD_TLS_TYPE;

		if (ioctl(fdc, CIOCAUTHCRYPT, &cao)) {
			perror("ioctl(CIOCAUTHCRYPT)");
			return 1;
		}
		total += cao.len;
	} while(!must_finish);
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
	int err;

	fd = open("/dev/crypto", O_RDWR, 0);
	if (fd < 0) {
		perror("open()");
		return fd;
	}
	if (ioctl(fd, CRIOGET, &fdc)) {
		perror("ioctl(CRIOGET)");
		return -EINVAL;
	}

	if (strcmp("authenc", ciphers[id].name) == 0) {
		tp.authflag = true;
	}

	if (!tp.mflag) {
		if (tp.authflag) {
			fprintf(stderr, "Testing %s:\n", ciphers[id].name);
		} else {
			char *type;
			type = tp.aflag ? "async" : "sync";

			fprintf(stderr, "Testing %s %s:\n", type, ciphers[id].name);
		}
	}
	err = ciphers[id].func(fdc, tp);

	close(fdc);
	close(fd);

	return err;
}

static int start_test (int fdc, struct test_params tp, struct session_op *sess)
{
	int err;

	if (tp.authflag) {
		err = encrypt_auth(fdc, tp, sess);
	} else {
		if (tp.aflag) {
			err = encrypt_async(fdc, tp, sess);
		} else {
			err = encrypt_sync(fdc, tp, sess);
		}
	}

	return err;
}

void do_test_vectors(int fdc, struct test_params tp, struct session_op *sess)
{
	int i;
	int err;

	if (tp.nflag) {
		err = start_test(fdc, tp, sess);
	} else {
		for (i = 256; i <= (64 * 1024); i *= 2) {
			if (must_exit) {
				break;
			}

			tp.nvalue = i;
			err = start_test(fdc, tp, sess);

			if (err != 0) {
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

	if (ioctl(fdc, CIOCFSESSION, &sess)) {
		perror("ioctl(CIOCFSESSION)");
		return -EINVAL;
	}

	return 0;
}

int run_aes_128_cbc(int fdc, struct test_params tp)
{
	struct session_op sess;
	char keybuf[32];

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

	if (ioctl(fdc, CIOCFSESSION, &sess)) {
		perror("ioctl(CIOCFSESSION)");
		return -EINVAL;
	}

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

	if (ioctl(fdc, CIOCFSESSION, &sess)) {
		perror("ioctl(CIOCFSESSION)");
		return -EINVAL;
	}

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

	if (ioctl(fdc, CIOCFSESSION, &sess)) {
		perror("ioctl(CIOCFSESSION)");
		return -EINVAL;
	}

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

	if (ioctl(fdc, CIOCFSESSION, &sess)) {
		perror("ioctl(CIOCFSESSION)");
		return -EINVAL;
	}

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

	if (ioctl(fdc, CIOCFSESSION, &sess)) {
		perror("ioctl(CIOCFSESSION)");
		return -EINVAL;
	}

	return 0;
}

int run_authenc(int fdc, struct test_params tp)
{
	struct session_op sess;
	char *mkeybuf = "\x00\x00\x00\x00\x00\x00\x00\x00"
		          "\x00\x00\x00\x00\x00\x00\x00\x00"
		          "\x00\x00\x00\x00";
	char *ckeybuf = "\x06\xa9\x21\x40\x36\xb8\xa1\x5b"
		          "\x51\x2e\x03\xd5\x34\x12\x00\x06";

	memset(&sess, 0, sizeof(sess));
	sess.cipher = CRYPTO_AUTHENC_HMAC_SHA1_CBC_AES;
	sess.keylen = 16;
	sess.key = (unsigned char *)ckeybuf;
	sess.mackeylen = 20;
	sess.mackey = (unsigned char *)mkeybuf;
	if (ioctl(fdc, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return -EINVAL;
	}

	do_test_vectors(fdc, tp, &sess);

	if (ioctl(fdc, CIOCFSESSION, &sess)) {
		perror("ioctl(CIOCFSESSION)");
		return -EINVAL;
	}

	return 0;
}

char *n_2048 = "\xFA\xBE\x23\x01\x5D\x11\x50\xAA\xAB\xED\x50\xA7\x9B\x93\x7B\xCE"
		"\x1E\x11\xAE\xC1\x05\xAF\xBA\x57\x18\x6B\xE3\x27\x85\x3A\xFA\xB9"
		"\x15\x5A\x39\xB2\x38\x60\xB8\x5B\xDF\xD0\x8F\xA3\x37\xEE\xE5\xFD"
		"\xE2\x98\xF9\x40\xD2\x0A\xE9\x15\x69\x8A\x9D\xBC\x1F\x00\x0B\x95"
		"\x5A\x19\x14\x4C\x14\x19\x38\x47\x30\x96\x17\xCB\x28\x1C\x1C\x09"
		"\x14\x79\x55\x26\xAF\x6E\x38\x41\x91\x9D\xF5\x31\x6C\xFB\xCC\x68"
		"\x08\xA2\x60\xA2\xA4\xE0\x68\x59\x24\xF5\xEB\x57\x88\x5C\x3D\xA3"
		"\x41\x95\xFF\xD1\x03\xBA\xAE\x18\x55\x5D\xF4\x93\x57\x4D\x02\x11"
		"\x66\xD8\x44\xF8\x63\x9D\x70\xBE\x98\x93\x43\xE0\x1F\x80\x7A\xE1"
		"\x6D\xA0\x5D\xC3\xE5\x56\x1C\xDA\x96\x16\xB1\xD8\xBD\x62\x1E\x51"
		"\x28\xF7\x06\xB7\x6D\xB0\x5A\x5F\x09\x28\xEF\x9B\x33\xA3\x04\x02"
		"\x08\x4D\xD7\x2C\x22\x77\x3D\x9B\x2E\x45\xE7\x78\x5C\x64\x50\xF3"
		"\x5B\x98\x6E\x0F\xDE\xA6\xDC\x19\x4D\xFF\xAB\xBE\x6D\xC7\xB1\x55"
		"\x36\xDD\x40\x07\xEF\x78\xCC\xA1\x8D\x96\x6B\xDA\x48\x4C\x40\x29"
		"\x46\x7C\xF0\x1A\x6B\xC5\xBB\x8B\xD1\xB0\x6F\x9B\xB7\xC0\x06\xF5"
		"\x3B\x6F\x2B\x45\xEA\x17\x4C\x16\x2A\xC5\x5E\xB6\x1C\xCB\x3B\xFB";

char *f_2048 = "\x69\xeb\xb3\xb3\x68\xc1\xbf\x17\x57\x63\xca\xa2\x21\xee\x1f\x56"
		"\x8c\xee\x58\x96\x86\x86\x95\x44\xc7\xff\x75\xeb\xb4\xe8\xf6\x55"
		"\x20\xa0\xad\x62\x50\xe4\x83\x07\x31\xe9\x41\x03\xf3\x69\x9b\x9b"
		"\x0d\x68\xf3\x6e\x21\x02\x79\xc5\xa4\xd1\xe5\x11\x56\x9a\x2c\xb8"
		"\xf5\x76\xab\x04\x03\xcc\x6d\xa3\xf1\xa3\x6a\x57\xfd\x6e\x87\x82"
		"\xcf\x19\xf8\x0f\x97\x4d\x6e\xb5\xa0\x10\x27\x40\x12\x8b\x9f\x24"
		"\xb4\x4a\x95\xbe\x6a\x49\x49\x67\xb0\x8f\x77\x5f\x1d\x56\x22\xc6"
		"\x7d\xb3\x2f\x9e\x62\x4a\x0b\xf2\xca\x9e\xd1\x57\xf8\xf4\x25\x36"
		"\x54\xe9\x4a\xcd\x4d\x9b\x14\xd5\xe5\x35\x59\x6b\xf5\xd0\x50\x69"
		"\x5c\xde\x21\x32\xc9\x31\x8f\x21\x66\xda\x32\xb8\x45\x18\x18\x57"
		"\xb0\x37\xff\xea\xee\x7a\xd5\x01\x36\x72\xb3\xfb\x23\xe2\x5c\xa2"
		"\x10\xb9\xf3\x8b\xda\x37\x46\x7e\xac\xf5\x6c\xae\x18\x69\xbc\x9d"
		"\x6e\xd7\x61\x7c\x85\x63\x41\x5e\x8b\xab\x12\xbe\x37\x1a\x67\xdd"
		"\x86\xf2\xf9\xc8\x3a\xd7\xcd\x92\x72\xaf\xad\x46\xb0\x5b\x33\xd9"
		"\x1c\x32\x02\x3c\xae\xe0\x5d\x87\xde\x95\x59\x10\x4e\xa7\xdf\x7f"
		"\x94\x2d\xea\x9b\x7a\x53\x54\xc7\xf9\x66\xd1\x14\x0b\xd7\xef\x00";

char *n_1024 = "\xF8\x99\x5E\xC7\xED\x60\x4B\xBA\x77\x0A\x52\xD0\xFF\xE6\x45\x47"
		"\x04\xDE\xB3\x40\x16\x23\xB4\x58\x0A\xFF\xAF\x0D\x26\x1B\x5E\x0D"
		"\x61\xA2\x4A\x7B\x2E\x70\x2A\x54\x21\xCB\x01\x31\xBC\xBE\xAE\xC9"
		"\x5B\x3B\x20\x0B\x95\x06\x41\x03\xDB\xEF\x81\xE2\xFB\x42\xE8\x02"
		"\x1D\xD2\xA7\xFD\xC3\xA0\x3F\x74\x6D\x99\x8D\x60\xBA\x43\x82\x6C"
		"\x96\x24\x1D\xE5\xE3\x2C\xB7\x66\xAB\x2B\x4C\xFD\x23\xFF\xE0\x09"
		"\x17\x3E\x01\xCB\xDC\xB2\xD2\xA9\x98\x99\x01\x91\x16\xAB\x77\xD7"
		"\x97\x52\xBD\x49\xB2\xAF\x61\x95\xE8\xA2\x34\x9C\xC4\x00\xCC\x17";

char *f_1024 = "\x8f\x2d\x06\x83\xee\x08\x97\xa4\x86\x3a\xf2\xa3\xd1\x6d\x33\x10"
		"\x49\x1d\xb6\xd0\xe3\x7b\x16\x5a\x1a\x5c\x98\x36\xab\xd2\xa9\x82"
		"\x5c\x1b\xc1\x9e\xdc\x50\x45\x05\xe0\x2e\x14\x83\x86\x47\x21\xc5"
		"\x27\xad\xb1\x74\x5d\x7b\xe2\x92\xfc\x15\xf0\x14\x6c\x8d\x80\xe5"
		"\x85\x72\x26\xc7\xa3\xd8\xc7\x5a\x10\xcd\x64\xde\x5d\x82\xc1\x53"
		"\xd7\x2e\x03\xe0\xe2\xe6\xc6\x85\xcc\x07\x25\xa9\x61\xf7\x52\x3f"
		"\x63\xb1\x54\x6e\x23\xbe\xf0\x6c\xa4\x93\x8c\x39\xe2\xdb\xcb\x1c"
		"\x4b\x95\x3d\x57\x06\xc9\xce\x44\xe5\xaf\xac\x6b\x67\xdb\x92\x00";

int run_rsa(int fdc, struct test_params tp)
{
	struct timeval start, end;
	double secs, ddata, dspeed;
	uint64_t total = 0;
	char metric[16];
	struct crypt_kop kop;
	char *n, *f;
	char *e = "\x01\x00\x01";
	char g[256];

	if (!tp.nflag)
		tp.nvalue = 2048;

	switch (tp.nvalue) {
		case 2048:
			n = n_2048;
			f = f_2048;
			break;

		case 1024:
			n = n_1024;
			f = f_1024;
			break;

		default:
			if (!tp.mflag) {
				printf("Error: rsa-%d not supported\n", tp.nvalue);
				fflush(stdout);
			}

			return 1;
	}

	kop.crk_op = CRK_MOD_EXP;
	kop.crk_iparams = 3;
	kop.crk_oparams = 1;

	kop.crk_param[0].crp_p = (__u8*)f;
	kop.crk_param[0].crp_nbits = tp.nvalue;

	kop.crk_param[1].crp_p = (__u8*)e;
	kop.crk_param[1].crp_nbits = 24;

	kop.crk_param[2].crp_p = (__u8*)n;
	kop.crk_param[2].crp_nbits = tp.nvalue;

	kop.crk_param[3].crp_p = (__u8*)g;
	kop.crk_param[3].crp_nbits = sizeof(g) << 3;

	if (!tp.mflag) {
		printf("\trsa %d: ", tp.nvalue);
		fflush(stdout);
	}

	must_finish = 0;
	alarm(tp.tvalue);

	gettimeofday(&start, NULL);
	do {
		if (ioctl(fdc, CIOCKEY, &kop)) {
			perror("ioctl(CIOCKEY)");
			return -EINVAL;
		}
		total += (tp.nvalue >> 3);
	} while (!must_finish);
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

	return 0;
}

int main(int argc, char **argv)
{
	int err = 0;
	int i;
	int c;
	bool alg_flag;
	char *alg_name;
	struct test_params tp;

	tp.tflag = false;
	tp.nflag = false;
	tp.mflag = false;
	tp.aflag = false;
	tp.authflag = false;
	alg_flag = false;
	opterr = 0;
	while ((c = getopt(argc, argv, "ahn:t:m")) != -1) {
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
		case 'a':
			tp.aflag = true;
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
		if (must_exit) {
			break;
		}

		if (alg_flag) {
			if (strcmp(alg_name, ciphers[i].name) == 0) {
				err = run_test(i, tp);
			}
		} else {
			err = run_test(i, tp);
			if (err != 0) {
				break;
			}
		}
	}

	return err;
}
