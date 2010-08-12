/*
 * Demo on how to use /dev/crypto device for HMAC.
 *
 * Placed under public domain.
 *
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/netlink.h>
#include "../ncr.h"
#include <stdlib.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#if GNUTLS_VERSION_NUMBER >= 0x020b00
# include <gnutls/abstract.h>
#endif

#define DATA_SIZE 4096

#define ALIGN_NL __attribute__((aligned(NLA_ALIGNTO)))

static void
print_hex_datum (gnutls_datum_t * dat)
{
  unsigned int j;
#define SPACE "\t"
  fprintf (stdout, "\n" SPACE);
  for (j = 0; j < dat->size; j++)
    {
      fprintf (stdout, "%.2x:", (unsigned char) dat->data[j]);
      if ((j + 1) % 15 == 0)
	fprintf (stdout, "\n" SPACE);
    }
  fprintf (stdout, "\n");
}

static void
print_dsa_pkey (gnutls_datum_t * x, gnutls_datum_t * y, gnutls_datum_t * p,
		gnutls_datum_t * q, gnutls_datum_t * g)
{
  if (x) 
    {
      fprintf (stdout, "private key:");
      print_hex_datum (x);
    }
  fprintf (stdout, "public key:");
  print_hex_datum (y);
  fprintf (stdout, "p:");
  print_hex_datum (p);
  fprintf (stdout, "q:");
  print_hex_datum (q);
  fprintf (stdout, "g:");
  print_hex_datum (g);
}

static void
print_rsa_pkey (gnutls_datum_t * m, gnutls_datum_t * e, gnutls_datum_t * d,
		gnutls_datum_t * p, gnutls_datum_t * q, gnutls_datum_t * u,
		gnutls_datum_t * exp1, gnutls_datum_t *exp2)
{
  fprintf (stdout, "modulus:");
  print_hex_datum (m);
  fprintf (stdout, "public exponent:");
  print_hex_datum (e);
  if (d) 
    {
      fprintf (stdout, "private exponent:");
      print_hex_datum (d);
      fprintf (stdout, "prime1:");
      print_hex_datum (p);
      fprintf (stdout, "prime2:");
      print_hex_datum (q);
      fprintf (stdout, "coefficient:");
      print_hex_datum (u);
      if (exp1 && exp2)
        {
          fprintf (stdout, "exp1:");
          print_hex_datum (exp1);
          fprintf (stdout, "exp2:");
          print_hex_datum (exp2);
        }
    }
}

static const char *
raw_to_string (const unsigned char *raw, size_t raw_size)
{
	static char buf[1024];
	size_t i;
	if (raw_size == 0)
		return NULL;

	if (raw_size * 3 + 1 >= sizeof (buf))
		return NULL;

	for (i = 0; i < raw_size; i++) {
		sprintf (&(buf[i * 3]), "%02X%s", raw[i],
			(i == raw_size - 1) ? "" : ":");
	}
	buf[sizeof (buf) - 1] = '\0';

	return buf;
}

int privkey_info (void* data, int data_size, int verbose)
{
	gnutls_x509_privkey_t key;
	size_t size;
	int ret;
	gnutls_datum_t der;
	unsigned char buffer[5*1024];
	const char *cprint;

	ret = gnutls_x509_privkey_init (&key);
	if (ret < 0) {
		fprintf(stderr, "error in privkey_init\n");
		return 1;
	}

	der.data = data;
	der.size = data_size;

	ret = gnutls_x509_privkey_import (key, &der, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		fprintf(stderr, "unable to import privkey\n");
		return 1;
	}

	if (verbose > 0) {
		/* Public key algorithm
		*/
		fprintf (stdout, "Public Key Info:\n");
		ret = gnutls_x509_privkey_get_pk_algorithm (key);

		fprintf (stdout, "\tPublic Key Algorithm: ");
		cprint = gnutls_pk_algorithm_get_name (ret);
		fprintf (stdout, "%s\n", cprint ? cprint : "Unknown");

		/* Print the raw public and private keys
		*/
		if (ret == GNUTLS_PK_RSA) {
			gnutls_datum_t m, e, d, p, q, u, exp1={NULL,0}, exp2={NULL,0};

#if GNUTLS_VERSION_NUMBER >= 0x020b00
			ret = gnutls_x509_privkey_export_rsa_raw2 (key, &m, &e, &d, &p, &q, &u, &exp1, &exp2);
#else
			ret = gnutls_x509_privkey_export_rsa_raw (key, &m, &e, &d, &p, &q, &u);
#endif
			if (ret < 0)
				fprintf (stderr, "Error in key RSA data export: %s\n",
					gnutls_strerror (ret));
			else {
				print_rsa_pkey (&m, &e, &d, &p, &q, &u, &exp1, &exp2);
				gnutls_free (m.data);
				gnutls_free (e.data);
				gnutls_free (d.data);
				gnutls_free (p.data);
				gnutls_free (q.data);
				gnutls_free (u.data);
				gnutls_free (exp1.data);
				gnutls_free (exp2.data);
			}
		} else if (ret == GNUTLS_PK_DSA) {
			gnutls_datum_t p, q, g, y, x;

			ret = gnutls_x509_privkey_export_dsa_raw (key, &p, &q, &g, &y, &x);
			if (ret < 0)
				fprintf (stderr, "Error in key DSA data export: %s\n",
					gnutls_strerror (ret));
			else {
				print_dsa_pkey (&x, &y, &p, &q, &g);
				gnutls_free (x.data);
				gnutls_free (y.data);
				gnutls_free (p.data);
				gnutls_free (q.data);
				gnutls_free (g.data);
			}
		}

		fprintf (stdout, "\n");

		size = sizeof (buffer);
		if ((ret = gnutls_x509_privkey_get_key_id (key, 0, buffer, &size)) < 0) {
			fprintf (stderr, "Error in key id calculation: %s\n",
			       gnutls_strerror (ret));
		} else {
			fprintf (stdout, "Public Key ID: %s\n", raw_to_string (buffer, size));
		}

		size = sizeof (buffer);
		ret = gnutls_x509_privkey_export (key, GNUTLS_X509_FMT_PEM, buffer, &size);
		if (ret < 0) {
			fprintf(stderr, "Error in privkey_export\n");
			return 1;
		}

		fprintf (stdout, "\n%s\n", buffer);
	}

	gnutls_x509_privkey_deinit (key);
	
	return 0;
}



int pubkey_info(void* data, int data_size, int verbose)
{
#if GNUTLS_VERSION_NUMBER >= 0x020b00
	gnutls_pubkey_t key;
	size_t size;
	int ret;
	gnutls_datum_t der;
	unsigned char buffer[5*1024];
	const char *cprint;

	ret = gnutls_pubkey_init (&key);
	if (ret < 0) {
		fprintf(stderr, "error in pubkey_init\n");
		return 1;
	}

	der.data = data;
	der.size = data_size;

	ret = gnutls_pubkey_import (key, &der, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		fprintf(stderr, "unable to import pubkey\n");
		return 1;
	}

	if (verbose > 0) {
		/* Public key algorithm
		*/
		fprintf (stdout, "Public Key Info:\n");
		ret = gnutls_pubkey_get_pk_algorithm (key, NULL);

		fprintf (stdout, "\tPublic Key Algorithm: ");
		cprint = gnutls_pk_algorithm_get_name (ret);
		fprintf (stdout, "%s\n", cprint ? cprint : "Unknown");

		/* Print the raw public and private keys
		*/
		if (ret == GNUTLS_PK_RSA) {
			gnutls_datum_t m, e;

			ret = gnutls_pubkey_get_pk_rsa_raw (key, &m, &e);
			if (ret < 0)
				fprintf (stderr, "Error in key RSA data export: %s\n",
					gnutls_strerror (ret));
			else {
				print_rsa_pkey (&m, &e, NULL, NULL, NULL, NULL, NULL, NULL);
				gnutls_free (m.data);
				gnutls_free (e.data);
			}
		} else if (ret == GNUTLS_PK_DSA) {
			gnutls_datum_t p, q, g, y;

			ret = gnutls_pubkey_get_pk_dsa_raw (key, &p, &q, &g, &y);
			if (ret < 0)
				fprintf (stderr, "Error in key DSA data export: %s\n",
					gnutls_strerror (ret));
			else {
				print_dsa_pkey (NULL, &y, &p, &q, &g);
				gnutls_free (y.data);
				gnutls_free (p.data);
				gnutls_free (q.data);
				gnutls_free (g.data);
			}
		}

		fprintf (stdout, "\n");

		size = sizeof (buffer);
		if ((ret = gnutls_pubkey_get_key_id (key, 0, buffer, &size)) < 0) {
			fprintf (stderr, "Error in key id calculation: %s\n",
			       gnutls_strerror (ret));
		} else {
			fprintf (stdout, "Public Key ID: %s\n", raw_to_string (buffer, size));
		}

		size = sizeof (buffer);
		ret = gnutls_pubkey_export (key, GNUTLS_X509_FMT_PEM, buffer, &size);
		if (ret < 0) {
			fprintf(stderr, "Error in privkey_export\n");
			return 1;
		}

		fprintf (stdout, "\n%s\n", buffer);
	}

	gnutls_pubkey_deinit (key);
#endif
	return 0;
}

/* Diffie Hellman */
const char dh_params_txt[] = "-----BEGIN DH PARAMETERS-----\n"\
"MIGHAoGBAKMox0/IjuGqSaGMJESYMhdmXiTe1pY8gkSzWZ/ktWaUdaYAzgAZp7r3\n"\
"OCh68YslS9Oi7/UQjmBbgGuOucMKgq3tYeYzY8G2epIuIzM4TAogaEqwkdSrXlth\n"\
"MMsP2FhLhHg8m6V6iItitnMOz9r8t3BEf04GRlfzgZraM0gUUwTjAgEF\n"\
"-----END DH PARAMETERS-----\n";

static int test_ncr_dh(int cfd)
{
struct __attribute__((packed)) {
	struct ncr_key_generate_pair f;
	struct nlattr algo_head ALIGN_NL;
	uint32_t algo ALIGN_NL;
	struct nlattr flags_head ALIGN_NL;
	uint32_t flags ALIGN_NL;
	unsigned char buffer[DATA_SIZE] ALIGN_NL;
} kgen;
struct nlattr *nla;
ncr_key_t private1, public1, public2, private2;
ncr_key_t z1, z2;
int ret;
gnutls_datum g, p, params;
gnutls_dh_params_t dhp;
unsigned char y1[1024], y2[1024];
size_t y1_size, y2_size;
struct ncr_key_data_st keydata;
struct ncr_key_derivation_params_st kderive;

	fprintf(stdout, "Tests on DH key exchange:");
	fflush(stdout);

	params.data = (void*)dh_params_txt;
	params.size = sizeof(dh_params_txt)-1;

	ret = gnutls_dh_params_init(&dhp);
	if (ret < 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		fprintf(stderr, "gnutls: %s\n", gnutls_strerror(ret));
		return 1;
	}
	
	ret = gnutls_dh_params_import_pkcs3(dhp, &params, GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		fprintf(stderr, "gnutls: %s\n", gnutls_strerror(ret));
		return 1;
	}
	
	ret = gnutls_dh_params_export_raw(dhp, &p, &g, NULL);
	if (ret < 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		fprintf(stderr, "gnutls: %s\n", gnutls_strerror(ret));
		return 1;
	}

	/* generate a DH key */
	private1 = ioctl(cfd, NCRIO_KEY_INIT);
	if (private1 == -1) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	public1 = ioctl(cfd, NCRIO_KEY_INIT);
	if (public1 == -1) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}
	
	memset(&kgen.f, 0, sizeof(kgen.f));
	kgen.f.private_key = private1;
	kgen.f.public_key = public1;
	kgen.algo_head.nla_len = NLA_HDRLEN + sizeof(kgen.algo);
	kgen.algo_head.nla_type = NCR_ATTR_ALGORITHM;
	kgen.algo = NCR_ALG_DH;
	kgen.flags_head.nla_len = NLA_HDRLEN + sizeof(kgen.flags);
	kgen.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
	kgen.flags = NCR_KEY_FLAG_EXPORTABLE;
	nla = (struct nlattr *)kgen.buffer;
	nla->nla_len = NLA_HDRLEN + p.size;
	nla->nla_type = NCR_ATTR_DH_PRIME;
	memcpy((char *)nla + NLA_HDRLEN, p.data, p.size);
	nla = (struct nlattr *)((char *)nla + NLA_ALIGN(nla->nla_len));
	nla->nla_len = NLA_HDRLEN + g.size;
	nla->nla_type = NCR_ATTR_DH_BASE;
	memcpy((char *)nla + NLA_HDRLEN, g.data, g.size);
	nla = (struct nlattr *)((char *)nla + NLA_ALIGN(nla->nla_len));
	kgen.f.input_size = (char *)nla - (char *)&kgen;
	assert(kgen.f.input_size <= sizeof(kgen));

	if (ioctl(cfd, NCRIO_KEY_GENERATE_PAIR, &kgen)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_GENERATE_PAIR)");
		return 1;
	}
	
	/* generate another DH key */
	private2 = ioctl(cfd, NCRIO_KEY_INIT);
	if (private2 == -1) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	public2 = ioctl(cfd, NCRIO_KEY_INIT);
	if (public2 == -1) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}
	
	memset(&kgen.f, 0, sizeof(kgen.f));
	kgen.f.private_key = private2;
	kgen.f.public_key = public2;
	kgen.algo_head.nla_len = NLA_HDRLEN + sizeof(kgen.algo);
	kgen.algo_head.nla_type = NCR_ATTR_ALGORITHM;
	kgen.algo = NCR_ALG_DH;
	kgen.flags_head.nla_len = NLA_HDRLEN + sizeof(kgen.flags);
	kgen.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
	kgen.flags = NCR_KEY_FLAG_EXPORTABLE;
	nla = (struct nlattr *)kgen.buffer;
	nla->nla_len = NLA_HDRLEN + p.size;
	nla->nla_type = NCR_ATTR_DH_PRIME;
	memcpy((char *)nla + NLA_HDRLEN, p.data, p.size);
	nla = (struct nlattr *)((char *)nla + NLA_ALIGN(nla->nla_len));
	nla->nla_len = NLA_HDRLEN + g.size;
	nla->nla_type = NCR_ATTR_DH_BASE;
	memcpy((char *)nla + NLA_HDRLEN, g.data, g.size);
	nla = (struct nlattr *)((char *)nla + NLA_ALIGN(nla->nla_len));
	kgen.f.input_size = (char *)nla - (char *)&kgen;
	assert(kgen.f.input_size <= sizeof(kgen));

	if (ioctl(cfd, NCRIO_KEY_GENERATE_PAIR, &kgen)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_GENERATE_PAIR)");
		return 1;
	}

	/* export y1=g^x1 */
	memset(&keydata, 0, sizeof(keydata));
	keydata.key = public1;
	keydata.idata = y1;
	keydata.idata_size = sizeof(y1);

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_EXPORT)");
		return 1;
	}
	
	y1_size = keydata.idata_size;

	/* export y2=g^x2 */
	memset(&keydata, 0, sizeof(keydata));
	keydata.key = public2;
	keydata.idata = y2;
	keydata.idata_size = sizeof(y2);

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_EXPORT)");
		return 1;
	}
	
	y2_size = keydata.idata_size;
	
	/* z1=y1^x2 */
	z1 = ioctl(cfd, NCRIO_KEY_INIT);
	if (z1 == -1) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	memset(&kderive, 0, sizeof(kderive));
	kderive.derive = NCR_DERIVE_DH;
	kderive.newkey = z1;
	kderive.keyflags = NCR_KEY_FLAG_EXPORTABLE;
	kderive.key = private1;
	kderive.params.params.dh.pub = y2;
	kderive.params.params.dh.pub_size = y2_size;

	if (ioctl(cfd, NCRIO_KEY_DERIVE, &kderive)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}
	
	/* z2=y2^x1 */
	z2 = ioctl(cfd, NCRIO_KEY_INIT);
	if (z2 == -1) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	memset(&kderive, 0, sizeof(kderive));
	kderive.derive = NCR_DERIVE_DH;
	kderive.newkey = z2;
	kderive.keyflags = NCR_KEY_FLAG_EXPORTABLE;
	kderive.key = private2;
	kderive.params.params.dh.pub = y1;
	kderive.params.params.dh.pub_size = y1_size;

	if (ioctl(cfd, NCRIO_KEY_DERIVE, &kderive)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}
	
	/* z1==z2 */
	memset(&keydata, 0, sizeof(keydata));
	keydata.key = z1;
	keydata.idata = y1;
	keydata.idata_size = sizeof(y1);

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_EXPORT)");
		return 1;
	}
	y1_size = keydata.idata_size;

	memset(&keydata, 0, sizeof(keydata));
	keydata.key = z2;
	keydata.idata = y2;
	keydata.idata_size = sizeof(y2);

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_EXPORT)");
		return 1;
	}
	y2_size = keydata.idata_size;
	
	if (y1_size == 0 || y1_size != y2_size || memcmp(y1, y2, y1_size) != 0) {
		int i;

		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		fprintf(stderr, "Output in DH does not match (%d, %d)!\n", 
			(int)y1_size, (int)y2_size);

		fprintf(stderr, "Key1[%d]: ", (int) y1_size);
		for(i=0;i<y1_size;i++)
			fprintf(stderr, "%.2x:", y1[i]);
		fprintf(stderr, "\n");

		fprintf(stderr, "Key2[%d]: ", (int) y2_size);
		for(i=0;i<y2_size;i++)
			fprintf(stderr, "%.2x:", y2[i]);
		fprintf(stderr, "\n");

		return 1;
	}


	fprintf(stdout, " Success\n");

	return 0;
}

/* check whether wrapping of long keys is not allowed with
 * shorted wrapping keys */
static int
test_ncr_wrap_key3(int cfd)
{
	int ret, i;
	ncr_key_t key;
	size_t data_size;
	struct ncr_key_data_st keydata;
	struct ncr_key_wrap_st kwrap;
	struct __attribute__((packed)) {
		struct ncr_key_generate_pair f;
		struct nlattr algo_head ALIGN_NL;
		uint32_t algo ALIGN_NL;
		struct nlattr flags_head ALIGN_NL;
		uint32_t flags ALIGN_NL;
		struct nlattr bits_head ALIGN_NL;
		uint32_t bits ALIGN_NL;
	} kgen;
	ncr_key_t pubkey, privkey;
	uint8_t data[DATA_SIZE];
	/* only the first two should be allowed to be wrapped.
	 * the latter shouldn't because it has security level larger
	 * then 128 bits (the size of the wrapping key).
	 */
	const int sizes[] = {1024, 3248, 5200};

	fprintf(stdout, "Tests on key wrapping (might take long): ");
	fflush(stdout);

	/* convert it to key */
	if (ioctl(cfd, NCRIO_KEY_INIT, &privkey)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	if (ioctl(cfd, NCRIO_KEY_INIT, &pubkey)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	if (geteuid() != 0) {
		/* cannot test further */
		fprintf(stdout, "\t(Wrapping test not completed. Run as root)\n");
		return 0;
	}

	/* make a wrapping key */
	if (ioctl(cfd, NCRIO_KEY_INIT, &key)) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	keydata.key_id[0] = 'a';
	keydata.key_id[2] = 'b';
	keydata.key_id_size = 2;
	keydata.type = NCR_KEY_TYPE_SECRET;
	keydata.algorithm = NCR_ALG_AES_CBC;
	keydata.flags = NCR_KEY_FLAG_EXPORTABLE|NCR_KEY_FLAG_WRAPPING;
	
	keydata.key = key;
	keydata.idata = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
	keydata.idata_size = 16;

	if (ioctl(cfd, NCRIO_KEY_IMPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}
	
	for (i=0;i<sizeof(sizes)/sizeof(sizes[0]);i++) {
	
		fprintf(stdout, ".");
		fflush(stdout);
		
		memset(&kgen.f, 0, sizeof(kgen.f));
		kgen.f.input_size = sizeof(kgen);
		kgen.f.private_key = privkey;
		kgen.f.public_key = pubkey;
		kgen.algo_head.nla_len = NLA_HDRLEN + sizeof(kgen.algo);
		kgen.algo_head.nla_type = NCR_ATTR_ALGORITHM;
		kgen.algo = NCR_ALG_RSA;
		kgen.flags_head.nla_len = NLA_HDRLEN + sizeof(kgen.flags);
		kgen.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
		kgen.flags = NCR_KEY_FLAG_EXPORTABLE|NCR_KEY_FLAG_WRAPPABLE;
		kgen.bits_head.nla_len = NLA_HDRLEN + sizeof(kgen.bits);
		kgen.bits_head.nla_type = NCR_ATTR_RSA_MODULUS_BITS;
		kgen.bits = sizes[i];

		if (ioctl(cfd, NCRIO_KEY_GENERATE_PAIR, &kgen)) {
			fprintf(stderr, "Error[%d-%d]: %s:%d\n", i, sizes[i], __func__, __LINE__);
			perror("ioctl(NCRIO_KEY_GENERATE_PAIR)");
			return 1;
		}

		/* now try wrapping key2 using key */
		memset(&kwrap, 0, sizeof(kwrap));
		kwrap.algorithm = NCR_WALG_AES_RFC5649;
		kwrap.keytowrap = pubkey;
		kwrap.key = key;
		kwrap.io = data;
		kwrap.io_size = sizeof(data);

		ret = ioctl(cfd, NCRIO_KEY_WRAP, &kwrap);
		if (ret) {
			fprintf(stderr, "Error[%d-%d]: %s:%d\n", i, sizes[i], __func__, __LINE__);
			/* wrapping of public key should have been allowed! */
			return 1;
		}

		/* now try wrapping private using key */
		memset(&kwrap, 0, sizeof(kwrap));
		kwrap.algorithm = NCR_WALG_AES_RFC5649;
		kwrap.keytowrap = privkey;
		kwrap.key = key;
		kwrap.io = data;
		kwrap.io_size = sizeof(data);

		ret = ioctl(cfd, NCRIO_KEY_WRAP, &kwrap);
		if (ret && i != 2) {
			fprintf(stderr, "Error[%d-%d]: %s:%d\n", i, sizes[i], __func__, __LINE__);
			/* wrapping should have been allowed */
			return 1;
		} else if (ret == 0 && i == 2) {
			fprintf(stderr, "Error[%d-%d]: %s:%d\n", i, sizes[i], __func__, __LINE__);
			/* wrapping shouldn't have been allowed */
			return 1;
		}			

		if (ret == 0) {
			data_size = kwrap.io_size;

			/* try unwrapping */
			memset(&kwrap, 0, sizeof(kwrap));
			kwrap.algorithm = NCR_WALG_AES_RFC5649;
			kwrap.wrapped_key_algorithm = NCR_ALG_RSA;
			kwrap.keytowrap = privkey;
			kwrap.key = key;
			kwrap.io = data;
			kwrap.io_size = data_size;

			ret = ioctl(cfd, NCRIO_KEY_UNWRAP, &kwrap);
			if (ret) {
				fprintf(stderr, "Error[%d-%d]: %s:%d\n", i, sizes[i], __func__, __LINE__);
				return 1;
			}			
		}
		fprintf(stdout, "*");
		fflush(stdout);

	}
	
	fprintf(stdout, " Success\n");
	return 0;
}

#define RSA_ENCRYPT_SIZE 32

static int rsa_key_encrypt(int cfd, ncr_key_t privkey, ncr_key_t pubkey, int oaep)
{
	struct ncr_session_once_op_st nop;
	uint8_t data[DATA_SIZE];
	uint8_t vdata[RSA_ENCRYPT_SIZE];
	int enc_size;

	fprintf(stdout, "Tests on RSA (%s) key encryption:", (oaep!=0)?"OAEP":"PKCS V1.5");
	fflush(stdout);

	memset(data, 0x3, sizeof(data));
	memcpy(vdata, data, sizeof(vdata));

	/* do encryption */
	memset(&nop, 0, sizeof(nop));
	nop.init.algorithm = NCR_ALG_RSA;
	nop.init.key = pubkey;
	if (oaep) {
		nop.init.params.params.rsa.type = RSA_PKCS1_OAEP;
		nop.init.params.params.rsa.oaep_hash = NCR_ALG_SHA1;
	} else {
		nop.init.params.params.rsa.type = RSA_PKCS1_V1_5;
	}
	nop.init.op = NCR_OP_ENCRYPT;
	nop.op.data.udata.input = data;
	nop.op.data.udata.input_size = RSA_ENCRYPT_SIZE;
	nop.op.data.udata.output = data;
	nop.op.data.udata.output_size = sizeof(data);
	nop.op.type = NCR_DIRECT_DATA;

	if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_SESSION_ONCE)");
		return 1;
	}
	
	enc_size = nop.op.data.udata.output_size;

	/* decrypt data */
	memset(&nop, 0, sizeof(nop));
	nop.init.algorithm = NCR_ALG_RSA;
	nop.init.key = privkey;
	nop.init.op = NCR_OP_DECRYPT;
	if (oaep) {
		nop.init.params.params.rsa.type = RSA_PKCS1_OAEP;
		nop.init.params.params.rsa.oaep_hash = NCR_ALG_SHA1;
	} else {
		nop.init.params.params.rsa.type = RSA_PKCS1_V1_5;
	}
	nop.op.data.udata.input = data;
	nop.op.data.udata.input_size = enc_size;
	nop.op.data.udata.output = data;
	nop.op.data.udata.output_size = sizeof(data);
	nop.op.type = NCR_DIRECT_DATA;


	if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_SESSION_ONCE)");
		return 1;
	}
	
	if (memcmp(vdata, data, sizeof(vdata)) != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		fprintf(stderr, "Decrypted data do not match!\n");
		return 1;
	}

	fprintf(stdout, " Success\n");

	return 0;

}

#define DATA_TO_SIGN 52

static int rsa_key_sign_verify(int cfd, ncr_key_t privkey, ncr_key_t pubkey, int pss)
{
	struct ncr_session_once_op_st nop;
	uint8_t data[DATA_SIZE];
	uint8_t sig[DATA_SIZE];
	int sig_size;

	fprintf(stdout, "Tests on RSA (%s) key signature:", (pss!=0)?"PSS":"PKCS V1.5");
	fflush(stdout);

	memset(data, 0x3, sizeof(data));

	/* sign datad */
	memset(&nop, 0, sizeof(nop));
	nop.init.algorithm = NCR_ALG_RSA;
	nop.init.key = privkey;
	nop.init.params.params.rsa.type = (pss!=0)?RSA_PKCS1_PSS:RSA_PKCS1_V1_5;
	nop.init.params.params.rsa.sign_hash = NCR_ALG_SHA1;

	nop.init.op = NCR_OP_SIGN;
	nop.op.data.udata.input = data;
	nop.op.data.udata.input_size = DATA_TO_SIGN;
	nop.op.data.udata.output = sig;
	nop.op.data.udata.output_size = sizeof(sig);
	nop.op.type = NCR_DIRECT_DATA;

	if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_SESSION_ONCE)");
		return 1;
	}
	
	sig_size = nop.op.data.udata.output_size;

	/* verify signature */
	memset(&nop, 0, sizeof(nop));
	nop.init.algorithm = NCR_ALG_RSA;
	nop.init.key = pubkey;
	nop.init.params.params.rsa.type = (pss!=0)?RSA_PKCS1_PSS:RSA_PKCS1_V1_5;
	nop.init.params.params.rsa.sign_hash = NCR_ALG_SHA1;

	memset(data, 0x3, sizeof(data));

	nop.init.op = NCR_OP_VERIFY;
	nop.op.data.udata.input = data;
	nop.op.data.udata.input_size = DATA_TO_SIGN;
	nop.op.data.udata.output = sig;
	nop.op.data.udata.output_size = sig_size;
	nop.op.type = NCR_DIRECT_DATA;

	if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_SESSION_ONCE)");
		return 1;
	}

	if (nop.op.err == NCR_SUCCESS)
		fprintf(stdout, " Success\n");
	else {
		fprintf(stdout, " Verification Failed!\n");
		return 1;
	}

	return 0;

}

static int dsa_key_sign_verify(int cfd, ncr_key_t privkey, ncr_key_t pubkey)
{
	struct ncr_session_once_op_st nop;
	uint8_t data[DATA_SIZE];
	uint8_t sig[DATA_SIZE];
	int sig_size;

	fprintf(stdout, "Tests on DSA key signature:");
	fflush(stdout);

	memset(data, 0x3, sizeof(data));

	/* sign datad */
	memset(&nop, 0, sizeof(nop));
	nop.init.algorithm = NCR_ALG_DSA;
	nop.init.key = privkey;
	nop.init.params.params.dsa.sign_hash = NCR_ALG_SHA1;

	nop.init.op = NCR_OP_SIGN;
	nop.op.data.udata.input = data;
	nop.op.data.udata.input_size = DATA_TO_SIGN;
	nop.op.data.udata.output = sig;
	nop.op.data.udata.output_size = sizeof(sig);
	nop.op.type = NCR_DIRECT_DATA;

	if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_SESSION_ONCE)");
		return 1;
	}
	
	sig_size = nop.op.data.udata.output_size;

	/* verify signature */
	memset(&nop, 0, sizeof(nop));
	nop.init.algorithm = NCR_ALG_DSA;
	nop.init.key = pubkey;
	nop.init.params.params.dsa.sign_hash = NCR_ALG_SHA1;

	nop.init.op = NCR_OP_VERIFY;
	nop.op.data.udata.input = data;
	nop.op.data.udata.input_size = DATA_TO_SIGN;
	nop.op.data.udata.output = sig;
	nop.op.data.udata.output_size = sizeof(sig);
	nop.op.type = NCR_DIRECT_DATA;

	if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_SESSION_ONCE)");
		return 1;
	}

	if (nop.op.err == NCR_SUCCESS)
		fprintf(stdout, " Success\n");
	else {
		fprintf(stdout, " Verification Failed!\n");
		return 1;
	}

	return 0;

}


static int test_ncr_rsa(int cfd)
{
	int ret;
	struct __attribute__((packed)) {
		struct ncr_key_generate_pair f;
		struct nlattr algo_head ALIGN_NL;
		uint32_t algo ALIGN_NL;
		struct nlattr flags_head ALIGN_NL;
		uint32_t flags ALIGN_NL;
		struct nlattr bits_head ALIGN_NL;
		uint32_t bits ALIGN_NL;
	} kgen;
	ncr_key_t pubkey, privkey;
	struct ncr_key_data_st keydata;
	uint8_t data[DATA_SIZE];
	int data_size;

	fprintf(stdout, "Tests on RSA key generation:");
	fflush(stdout);

	/* convert it to key */
	privkey = ioctl(cfd, NCRIO_KEY_INIT);
	if (privkey == -1) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	pubkey = ioctl(cfd, NCRIO_KEY_INIT);
	if (pubkey == -1) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	memset(&kgen, 0, sizeof(kgen));
	kgen.f.input_size = sizeof(kgen);
	kgen.f.private_key = privkey;
	kgen.f.public_key = pubkey;
	kgen.algo_head.nla_len = NLA_HDRLEN + sizeof(kgen.algo);
	kgen.algo_head.nla_type = NCR_ATTR_ALGORITHM;
	kgen.algo = NCR_ALG_RSA;
	kgen.flags_head.nla_len = NLA_HDRLEN + sizeof(kgen.flags);
	kgen.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
	kgen.flags = NCR_KEY_FLAG_EXPORTABLE|NCR_KEY_FLAG_WRAPPABLE;
	kgen.bits_head.nla_len = NLA_HDRLEN + sizeof(kgen.bits);
	kgen.bits_head.nla_type = NCR_ATTR_RSA_MODULUS_BITS;
	kgen.bits = 1024;

	if (ioctl(cfd, NCRIO_KEY_GENERATE_PAIR, &kgen)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_GENERATE_PAIR)");
		return 1;
	}

	/* export the private key */
	memset(data, 0, sizeof(data));
	memset(&keydata, 0, sizeof(keydata));
	keydata.key = privkey;
	keydata.idata = data;
	keydata.idata_size = sizeof(data);

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_EXPORT)");
		return 1;
	}
	
	data_size = keydata.idata_size;

	ret = privkey_info(data, data_size, 0);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}
	
	/* export the public key */

	memset(data, 0, sizeof(data));
	memset(&keydata, 0, sizeof(keydata));
	keydata.key = pubkey;
	keydata.idata = data;
	keydata.idata_size = sizeof(data);

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}
	
	data_size = keydata.idata_size;

	ret = pubkey_info(data, data_size, 0);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}

	fprintf(stdout, " Success\n");

	ret = rsa_key_sign_verify(cfd, privkey, pubkey, 1);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}

	ret = rsa_key_sign_verify(cfd, privkey, pubkey, 0);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}

	ret = rsa_key_encrypt(cfd, privkey, pubkey, 0);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}

	ret = rsa_key_encrypt(cfd, privkey, pubkey, 1);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}

	return 0;

}

static int test_ncr_dsa(int cfd)
{
	int ret;
	struct __attribute__((packed)) {
		struct ncr_key_generate_pair f;
		struct nlattr algo_head ALIGN_NL;
		uint32_t algo ALIGN_NL;
		struct nlattr flags_head ALIGN_NL;
		uint32_t flags ALIGN_NL;
		struct nlattr q_bits_head ALIGN_NL;
		uint32_t q_bits ALIGN_NL;
		struct nlattr p_bits_head ALIGN_NL;
		uint32_t p_bits ALIGN_NL;
	} kgen;
	ncr_key_t pubkey, privkey;
	struct ncr_key_data_st keydata;
	uint8_t data[DATA_SIZE];
	int data_size;

	fprintf(stdout, "Tests on DSA key generation:");
	fflush(stdout);

	/* convert it to key */
	privkey = ioctl(cfd, NCRIO_KEY_INIT);
	if (privkey == -1) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	pubkey = ioctl(cfd, NCRIO_KEY_INIT);
	if (pubkey == -1) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	memset(&kgen, 0, sizeof(kgen));
	kgen.f.input_size = sizeof(kgen);
	kgen.f.private_key = privkey;
	kgen.f.public_key = pubkey;
	kgen.algo_head.nla_len = NLA_HDRLEN + sizeof(kgen.algo);
	kgen.algo_head.nla_type = NCR_ATTR_ALGORITHM;
	kgen.algo = NCR_ALG_DSA;
	kgen.flags_head.nla_len = NLA_HDRLEN + sizeof(kgen.flags);
	kgen.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
	kgen.flags = NCR_KEY_FLAG_EXPORTABLE|NCR_KEY_FLAG_WRAPPABLE;
	kgen.q_bits_head.nla_len = NLA_HDRLEN + sizeof(kgen.q_bits);
	kgen.q_bits_head.nla_type = NCR_ATTR_DSA_Q_BITS;
	kgen.q_bits = 160;
	kgen.p_bits_head.nla_len = NLA_HDRLEN + sizeof(kgen.p_bits);
	kgen.p_bits_head.nla_type = NCR_ATTR_DSA_P_BITS;
	kgen.p_bits = 1024;

	if (ioctl(cfd, NCRIO_KEY_GENERATE_PAIR, &kgen)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_GENERATE_PAIR)");
		return 1;
	}

	memset(&keydata, 0, sizeof(keydata));
	memset(data, 0, sizeof(data));
	keydata.key = privkey;
	keydata.idata = data;
	keydata.idata_size = sizeof(data);

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_EXPORT)");
		return 1;
	}
	data_size = keydata.idata_size;

	ret = privkey_info(data, data_size, 0);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}
	
	/* export the public key */

	memset(data, 0, sizeof(data));
	memset(&keydata, 0, sizeof(keydata));
	keydata.key = pubkey;
	keydata.idata = data;
	keydata.idata_size = sizeof(data);

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}
	
	data_size = keydata.idata_size;

	ret = pubkey_info(data, data_size, 0);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}

	fprintf(stdout, " Success\n");

	ret = dsa_key_sign_verify(cfd, privkey, pubkey);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}

	return 0;

}


int
main()
{
	int fd = -1;

	gnutls_global_init();

	/* actually test if the initial close
	 * will really delete all used lists */

	fd = open("/dev/crypto", O_RDWR, 0);
	if (fd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}

	if (test_ncr_dh(fd))
		return 1;

	if (test_ncr_rsa(fd))
		return 1;

	if (test_ncr_dsa(fd))
		return 1;
		
	if (test_ncr_wrap_key3(fd))
		return 1;

	/* Close the original descriptor */
	if (close(fd)) {
		perror("close(fd)");
		return 1;
	}

	return 0;
}
