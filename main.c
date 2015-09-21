/*
 * Driver for /dev/crypto device (aka CryptoDev)
 *
 * Copyright (c) 2004 Michal Ludvig <mludvig@logix.net.nz>, SuSE Labs
 * Copyright (c) 2009-2013 Nikos Mavrogiannopoulos <nmav@gnutls.org>
 * Copyright (c) 2014 Freescale Semiconductor, Inc.
 *
 * This file is part of linux cryptodev.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/*
 * Device /dev/crypto provides an interface for
 * accessing kernel CryptoAPI algorithms (ciphers,
 * hashes) from userspace programs.
 *
 * /dev/crypto interface was originally introduced in
 * OpenBSD and this module attempts to keep the API.
 *
 */
#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/ioctl.h>
#include <linux/random.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>
#include <linux/poll.h>
#include <linux/uaccess.h>
#include <crypto/cryptodev.h>
#include <crypto/scatterwalk.h>
#include <linux/scatterlist.h>
#include "cryptodev_int.h"
#include "zc.h"
#include "cryptlib.h"
#include "version.h"

/* This file contains the traditional operations of encryption
 * and hashing of /dev/crypto.
 */

static int
hash_n_crypt(struct csession *ses_ptr, struct crypt_op *cop,
		struct scatterlist *src_sg, struct scatterlist *dst_sg,
		uint32_t len)
{
	int ret;

	/* Always hash before encryption and after decryption. Maybe
	 * we should introduce a flag to switch... TBD later on.
	 */
	if (cop->op == COP_ENCRYPT) {
		if (ses_ptr->hdata.init != 0) {
			ret = cryptodev_hash_update(&ses_ptr->hdata,
							src_sg, len);
			if (unlikely(ret))
				goto out_err;
		}
		if (ses_ptr->cdata.init != 0) {
			ret = cryptodev_cipher_encrypt(&ses_ptr->cdata,
							src_sg, dst_sg, len);

			if (unlikely(ret))
				goto out_err;
		}
	} else {
		if (ses_ptr->cdata.init != 0) {
			ret = cryptodev_cipher_decrypt(&ses_ptr->cdata,
							src_sg, dst_sg, len);

			if (unlikely(ret))
				goto out_err;
		}

		if (ses_ptr->hdata.init != 0) {
			ret = cryptodev_hash_update(&ses_ptr->hdata,
								dst_sg, len);
			if (unlikely(ret))
				goto out_err;
		}
	}
	return 0;
out_err:
	derr(0, "CryptoAPI failure: %d", ret);
	return ret;
}

/* This is the main crypto function - feed it with plaintext
   and get a ciphertext (or vice versa :-) */
static int
__crypto_run_std(struct csession *ses_ptr, struct crypt_op *cop)
{
	char *data;
	char __user *src, *dst;
	struct scatterlist sg;
	size_t nbytes, bufsize;
	int ret = 0;

	nbytes = cop->len;
	data = (char *)__get_free_page(GFP_KERNEL);

	if (unlikely(!data)) {
		derr(1, "Error getting free page.");
		return -ENOMEM;
	}

	bufsize = PAGE_SIZE < nbytes ? PAGE_SIZE : nbytes;

	src = cop->src;
	dst = cop->dst;

	while (nbytes > 0) {
		size_t current_len = nbytes > bufsize ? bufsize : nbytes;

		if (unlikely(copy_from_user(data, src, current_len))) {
		        derr(1, "Error copying %zu bytes from user address %p.", current_len, src);
			ret = -EFAULT;
			break;
		}

		sg_init_one(&sg, data, current_len);

		ret = hash_n_crypt(ses_ptr, cop, &sg, &sg, current_len);

		if (unlikely(ret)) {
		        derr(1, "hash_n_crypt failed.");
			break;
		}

		if (ses_ptr->cdata.init != 0) {
			if (unlikely(copy_to_user(dst, data, current_len))) {
			        derr(1, "could not copy to user.");
				ret = -EFAULT;
				break;
			}
		}

		dst += current_len;
		nbytes -= current_len;
		src += current_len;
	}

	free_page((unsigned long)data);
	return ret;
}



/* This is the main crypto function - zero-copy edition */
static int
__crypto_run_zc(struct csession *ses_ptr, struct kernel_crypt_op *kcop)
{
	struct scatterlist *src_sg, *dst_sg;
	struct crypt_op *cop = &kcop->cop;
	int ret = 0;

	ret = get_userbuf(ses_ptr, cop->src, cop->len, cop->dst, cop->len,
	                  kcop->task, kcop->mm, &src_sg, &dst_sg);
	if (unlikely(ret)) {
		derr(1, "Error getting user pages. Falling back to non zero copy.");
		return __crypto_run_std(ses_ptr, cop);
	}

	ret = hash_n_crypt(ses_ptr, cop, src_sg, dst_sg, cop->len);

	release_user_pages(ses_ptr);
	return ret;
}

int crypto_kop_dsasign(struct cryptodev_pkc *pkc)
{
	struct kernel_crypt_kop *kop = &pkc->kop;
	struct crypt_kop *cop = &kop->kop;
	struct dsa_sign_req_s *dsa_req = &pkc->req->req_u.dsa_sign;
	int rc, buf_size;
	uint8_t *buf;

	if (!cop->crk_param[0].crp_nbits || !cop->crk_param[1].crp_nbits ||
	    !cop->crk_param[2].crp_nbits || !cop->crk_param[3].crp_nbits ||
	    !cop->crk_param[4].crp_nbits || !cop->crk_param[5].crp_nbits ||
	    !cop->crk_param[6].crp_nbits || (cop->crk_iparams == 6 &&
	    !cop->crk_param[7].crp_nbits))
		return -EINVAL;

	dsa_req->m_len = (cop->crk_param[0].crp_nbits + 7)/8;
	dsa_req->q_len = (cop->crk_param[1].crp_nbits + 7)/8;
	dsa_req->r_len = (cop->crk_param[2].crp_nbits + 7)/8;
	dsa_req->g_len = (cop->crk_param[3].crp_nbits + 7)/8;
	dsa_req->priv_key_len = (cop->crk_param[4].crp_nbits + 7)/8;
	dsa_req->d_len = (cop->crk_param[6].crp_nbits + 7)/8;
	buf_size = dsa_req->m_len + dsa_req->q_len + dsa_req->r_len +
		   dsa_req->g_len + dsa_req->priv_key_len + dsa_req->d_len +
		   dsa_req->d_len;
	if (cop->crk_iparams == 6) {
		dsa_req->ab_len = (cop->crk_param[5].crp_nbits + 7)/8;
		buf_size += dsa_req->ab_len;
		pkc->req->curve_type = cop->curve_type;
	}

	buf = kmalloc(buf_size, GFP_DMA);
	if (!buf)
		return -ENOMEM;

	dsa_req->q = buf;
	dsa_req->r = dsa_req->q + dsa_req->q_len;
	dsa_req->g = dsa_req->r + dsa_req->r_len;
	dsa_req->priv_key = dsa_req->g + dsa_req->g_len;
	dsa_req->m = dsa_req->priv_key + dsa_req->priv_key_len;
	dsa_req->c = dsa_req->m + dsa_req->m_len;
	dsa_req->d = dsa_req->c + dsa_req->d_len;
	rc = copy_from_user(dsa_req->m, cop->crk_param[0].crp_p, dsa_req->m_len) ||
	     copy_from_user(dsa_req->q, cop->crk_param[1].crp_p, dsa_req->q_len) ||
	     copy_from_user(dsa_req->r, cop->crk_param[2].crp_p, dsa_req->r_len) ||
	     copy_from_user(dsa_req->g, cop->crk_param[3].crp_p, dsa_req->g_len) ||
	     copy_from_user(dsa_req->priv_key, cop->crk_param[4].crp_p, dsa_req->priv_key_len);
	if (cop->crk_iparams == 6) {
		dsa_req->ab = dsa_req->d + dsa_req->d_len;
		rc = rc || copy_from_user(dsa_req->ab, cop->crk_param[5].crp_p,
			       dsa_req->ab_len);
	}
	if (rc)
		goto err;

	rc = cryptodev_pkc_offload(pkc);
	if (pkc->type == SYNCHRONOUS) {
		if (cop->crk_iparams == 6) {
			rc = rc ||
			     copy_to_user(cop->crk_param[6].crp_p, dsa_req->c, dsa_req->d_len) ||
			     copy_to_user(cop->crk_param[7].crp_p, dsa_req->d, dsa_req->d_len);
		} else {
			rc = rc ||
			     copy_to_user(cop->crk_param[5].crp_p, dsa_req->c, dsa_req->d_len) ||
			     copy_to_user(cop->crk_param[6].crp_p, dsa_req->d, dsa_req->d_len);
		}
	} else {
		if (rc != -EINPROGRESS && rc != 0)
			goto err;

		pkc->cookie = buf;
		return rc;
	}
err:
	kfree(buf);
	return rc;
}

int crypto_kop_dsaverify(struct cryptodev_pkc *pkc)
{
	struct kernel_crypt_kop *kop = &pkc->kop;
	struct crypt_kop *cop = &kop->kop;
	struct dsa_verify_req_s *dsa_req;
	int rc, buf_size;
	uint8_t *buf;

	if (!cop->crk_param[0].crp_nbits || !cop->crk_param[1].crp_nbits ||
	    !cop->crk_param[2].crp_nbits || !cop->crk_param[3].crp_nbits ||
	    !cop->crk_param[4].crp_nbits || !cop->crk_param[5].crp_nbits ||
	    !cop->crk_param[6].crp_nbits  || (cop->crk_iparams == 8 &&
	    !cop->crk_param[7].crp_nbits))
		return -EINVAL;

	dsa_req = &pkc->req->req_u.dsa_verify;
	dsa_req->m_len = (cop->crk_param[0].crp_nbits + 7)/8;
	dsa_req->q_len = (cop->crk_param[1].crp_nbits + 7)/8;
	dsa_req->r_len = (cop->crk_param[2].crp_nbits + 7)/8;
	dsa_req->g_len = (cop->crk_param[3].crp_nbits + 7)/8;
	dsa_req->pub_key_len = (cop->crk_param[4].crp_nbits + 7)/8;
	dsa_req->d_len = (cop->crk_param[6].crp_nbits + 7)/8;
	buf_size = dsa_req->m_len + dsa_req->q_len + dsa_req->r_len +
		dsa_req->g_len + dsa_req->pub_key_len + dsa_req->d_len +
		dsa_req->d_len;
	if (cop->crk_iparams == 8) {
		dsa_req->ab_len = (cop->crk_param[5].crp_nbits + 7)/8;
		buf_size += dsa_req->ab_len;
		pkc->req->curve_type = cop->curve_type;
	}

	buf = kmalloc(buf_size, GFP_DMA);
	if (!buf)
		return -ENOMEM;

	dsa_req->q = buf;
	dsa_req->r = dsa_req->q + dsa_req->q_len;
	dsa_req->g = dsa_req->r + dsa_req->r_len;
	dsa_req->pub_key = dsa_req->g + dsa_req->g_len;
	dsa_req->m = dsa_req->pub_key + dsa_req->pub_key_len;
	dsa_req->c = dsa_req->m + dsa_req->m_len;
	dsa_req->d = dsa_req->c + dsa_req->d_len;
	rc = copy_from_user(dsa_req->m, cop->crk_param[0].crp_p, dsa_req->m_len) ||
	     copy_from_user(dsa_req->q, cop->crk_param[1].crp_p, dsa_req->q_len) ||
	     copy_from_user(dsa_req->r, cop->crk_param[2].crp_p, dsa_req->r_len) ||
	     copy_from_user(dsa_req->g, cop->crk_param[3].crp_p, dsa_req->g_len) ||
	     copy_from_user(dsa_req->pub_key, cop->crk_param[4].crp_p, dsa_req->pub_key_len);
	if (cop->crk_iparams == 8) {
		dsa_req->ab = dsa_req->d + dsa_req->d_len;
		rc = rc ||
		     copy_from_user(dsa_req->ab, cop->crk_param[5].crp_p, dsa_req->ab_len) ||
		     copy_from_user(dsa_req->c, cop->crk_param[6].crp_p, dsa_req->d_len) ||
		     copy_from_user(dsa_req->d, cop->crk_param[7].crp_p, dsa_req->d_len);
	} else {
		rc = rc ||
		     copy_from_user(dsa_req->c, cop->crk_param[5].crp_p, dsa_req->d_len) ||
		     copy_from_user(dsa_req->d, cop->crk_param[6].crp_p, dsa_req->d_len);
	}

	if (rc)
		goto err;

	rc = cryptodev_pkc_offload(pkc);
	if (pkc->type != SYNCHRONOUS) {
		if (rc != -EINPROGRESS && !rc)
			goto err;
		pkc->cookie = buf;
		return rc;
	}
err:
	kfree(buf);
	return rc;
}

int crypto_kop_rsa_keygen(struct cryptodev_pkc *pkc)
{
	struct kernel_crypt_kop *kop = &pkc->kop;
	struct crypt_kop *cop = &kop->kop;
	struct rsa_keygen_req_s *key_req;
	int rc, buf_size;
	uint8_t *buf;

	if (!cop->crk_param[0].crp_nbits || !cop->crk_param[1].crp_nbits ||
		!cop->crk_param[2].crp_nbits || !cop->crk_param[3].crp_nbits ||
		!cop->crk_param[4].crp_nbits || !cop->crk_param[5].crp_nbits ||
		!cop->crk_param[6].crp_nbits)
		return -EINVAL;

	key_req = &pkc->req->req_u.rsa_keygen;
	key_req->n_len = (cop->crk_param[2].crp_nbits + 7)/8;
	key_req->p_len = (cop->crk_param[0].crp_nbits + 7) / 8;
	key_req->q_len = (cop->crk_param[1].crp_nbits + 7) / 8;
	key_req->n_len = (cop->crk_param[2].crp_nbits + 7) / 8;
	key_req->d_len = (cop->crk_param[3].crp_nbits + 7) / 8;
	key_req->dp_len = (cop->crk_param[4].crp_nbits + 7) / 8;
	key_req->dq_len = (cop->crk_param[5].crp_nbits + 7) / 8;
	key_req->c_len = (cop->crk_param[6].crp_nbits + 7) / 8;

	buf_size = key_req->p_len + key_req->q_len + key_req->n_len +
			key_req->d_len + key_req->dp_len +
			key_req->dq_len + key_req->c_len;

	buf = kmalloc(buf_size, GFP_DMA);
	if (!buf)
		return -ENOMEM;
	key_req->p = buf;
	key_req->q = key_req->p + key_req->p_len;
	key_req->n = key_req->q + key_req->q_len;
	key_req->d = key_req->n + key_req->n_len;
	key_req->dp = key_req->d + key_req->d_len;
	key_req->dq = key_req->dp + key_req->dp_len;
	key_req->c = key_req->dq + key_req->dq_len;

	rc = cryptodev_pkc_offload(pkc);

	if (pkc->type == SYNCHRONOUS) {
		rc = rc ||
		     copy_to_user(cop->crk_param[0].crp_p, key_req->p, key_req->p_len) ||
		     copy_to_user(cop->crk_param[1].crp_p, key_req->q, key_req->q_len) ||
		     copy_to_user(cop->crk_param[2].crp_p, key_req->n, key_req->n_len) ||
		     copy_to_user(cop->crk_param[3].crp_p, key_req->d, key_req->d_len) ||
		     copy_to_user(cop->crk_param[4].crp_p, key_req->dp, key_req->dp_len) ||
		     copy_to_user(cop->crk_param[5].crp_p, key_req->dq, key_req->dq_len) ||
		     copy_to_user(cop->crk_param[6].crp_p, key_req->c, key_req->c_len);
	} else {
		if (rc != -EINPROGRESS && !rc) {
			printk("%s: Failed\n", __func__);
			goto err;
		}
		pkc->cookie = buf;
		return rc;
	}
err:
	kfree(buf);
	return rc;

}

int crypto_kop_keygen(struct cryptodev_pkc *pkc)
{
	struct kernel_crypt_kop *kop = &pkc->kop;
	struct crypt_kop *cop = &kop->kop;
	struct keygen_req_s *key_req;
	int rc, buf_size;
	uint8_t *buf;

	if (!cop->crk_param[0].crp_nbits || !cop->crk_param[1].crp_nbits ||
	    !cop->crk_param[2].crp_nbits || !cop->crk_param[3].crp_nbits ||
	    !cop->crk_param[4].crp_nbits)
		return -EINVAL;

	key_req = &pkc->req->req_u.keygen;
	key_req->q_len = (cop->crk_param[0].crp_nbits + 7)/8;
	key_req->r_len = (cop->crk_param[1].crp_nbits + 7)/8;
	key_req->g_len = (cop->crk_param[2].crp_nbits + 7)/8;
	if (cop->crk_iparams == 3) {
		key_req->pub_key_len = (cop->crk_param[3].crp_nbits + 7)/8;
		key_req->priv_key_len = (cop->crk_param[4].crp_nbits + 7)/8;
		buf_size = key_req->q_len + key_req->r_len + key_req->g_len +
			key_req->pub_key_len + key_req->priv_key_len;
	} else {
		key_req->ab_len = (cop->crk_param[3].crp_nbits + 7)/8;
		key_req->pub_key_len = (cop->crk_param[4].crp_nbits + 7)/8;
		key_req->priv_key_len = (cop->crk_param[5].crp_nbits + 7)/8;
		buf_size = key_req->q_len + key_req->r_len + key_req->g_len +
			key_req->pub_key_len + key_req->priv_key_len +
			key_req->ab_len;
		pkc->req->curve_type = cop->curve_type;
	}

	buf = kmalloc(buf_size, GFP_DMA);
	if (!buf)
		return -ENOMEM;
	key_req->q = buf;
	key_req->r = key_req->q + key_req->q_len;
	key_req->g = key_req->r + key_req->r_len;
	key_req->pub_key = key_req->g + key_req->g_len;
	key_req->priv_key = key_req->pub_key + key_req->pub_key_len;
	rc = copy_from_user(key_req->q, cop->crk_param[0].crp_p, key_req->q_len) ||
	     copy_from_user(key_req->r, cop->crk_param[1].crp_p, key_req->r_len) ||
	     copy_from_user(key_req->g, cop->crk_param[2].crp_p, key_req->g_len);

	if (cop->crk_iparams == 4) {
		key_req->ab = key_req->priv_key + key_req->priv_key_len;
		rc = rc || copy_from_user(key_req->ab, cop->crk_param[3].crp_p,
			       key_req->ab_len);
	}

	if (rc)
		goto err;

	rc = cryptodev_pkc_offload(pkc);
	if (pkc->type == SYNCHRONOUS) {
		if (cop->crk_iparams == 4) {
			rc = rc ||
			     copy_to_user(cop->crk_param[4].crp_p, key_req->pub_key,
				     key_req->pub_key_len) ||
			     copy_to_user(cop->crk_param[5].crp_p, key_req->priv_key,
				     key_req->priv_key_len);
		} else {
			rc = rc ||
			     copy_to_user(cop->crk_param[3].crp_p, key_req->pub_key,
				     key_req->pub_key_len) ||
			     copy_to_user(cop->crk_param[4].crp_p, key_req->priv_key,
				     key_req->priv_key_len);
		}
	} else {
		if (rc != -EINPROGRESS && !rc)
			goto err;

		pkc->cookie = buf;
		return rc;
	}
err:
	kfree(buf);
	return rc;
}

int crypto_kop_dh_key(struct cryptodev_pkc *pkc)
{
	struct kernel_crypt_kop *kop = &pkc->kop;
	struct crypt_kop *cop = &kop->kop;
	struct dh_key_req_s *dh_req;
	int buf_size;
	uint8_t *buf;
	int rc = 0;

	dh_req = &pkc->req->req_u.dh_req;
	dh_req->s_len = (cop->crk_param[0].crp_nbits + 7)/8;
	dh_req->pub_key_len = (cop->crk_param[1].crp_nbits + 7)/8;
	dh_req->q_len = (cop->crk_param[2].crp_nbits + 7)/8;
	buf_size = dh_req->q_len + dh_req->pub_key_len + dh_req->s_len;
	if (cop->crk_iparams == 4) {
		dh_req->ab_len = (cop->crk_param[3].crp_nbits + 7)/8;
		dh_req->z_len = (cop->crk_param[4].crp_nbits + 7)/8;
		buf_size += dh_req->ab_len;
	} else {
		dh_req->z_len = (cop->crk_param[3].crp_nbits + 7)/8;
	}
	buf_size += dh_req->z_len;
	buf = kmalloc(buf_size, GFP_DMA);
	if (!buf)
		return -ENOMEM;
	dh_req->q = buf;
	dh_req->s = dh_req->q + dh_req->q_len;
	dh_req->pub_key = dh_req->s + dh_req->s_len;
	dh_req->z = dh_req->pub_key + dh_req->pub_key_len;
	if (cop->crk_iparams == 4) {
		dh_req->ab = dh_req->z + dh_req->z_len;
		pkc->req->curve_type = cop->curve_type;
		rc = copy_from_user(dh_req->ab, cop->crk_param[3].crp_p, dh_req->ab_len);
	}

	rc = rc ||
	     copy_from_user(dh_req->s, cop->crk_param[0].crp_p, dh_req->s_len) ||
	     copy_from_user(dh_req->pub_key, cop->crk_param[1].crp_p, dh_req->pub_key_len) ||
	     copy_from_user(dh_req->q, cop->crk_param[2].crp_p, dh_req->q_len);
	if (rc)
		goto err;

	rc = cryptodev_pkc_offload(pkc);
	if (pkc->type == SYNCHRONOUS) {
		if (cop->crk_iparams == 4)
			rc = rc || copy_to_user(cop->crk_param[4].crp_p, dh_req->z,
				     dh_req->z_len);
		else
			rc = rc || copy_to_user(cop->crk_param[3].crp_p, dh_req->z,
				     dh_req->z_len);
	} else {
		if (rc != -EINPROGRESS && rc != 0)
			goto err;

		pkc->cookie = buf;
		return rc;
	}
err:
	kfree(buf);
	return rc;
}

int crypto_modexp_crt(struct cryptodev_pkc *pkc)
{
	struct kernel_crypt_kop *kop = &pkc->kop;
	struct crypt_kop *cop = &kop->kop;
	struct rsa_priv_frm3_req_s *rsa_req;
	int rc;
	uint8_t *buf;

	if (!cop->crk_param[0].crp_nbits || !cop->crk_param[1].crp_nbits ||
	    !cop->crk_param[2].crp_nbits || !cop->crk_param[3].crp_nbits ||
	    !cop->crk_param[4].crp_nbits || !cop->crk_param[5].crp_nbits)
		return -EINVAL;

	rsa_req = &pkc->req->req_u.rsa_priv_f3;
	rsa_req->p_len = (cop->crk_param[0].crp_nbits + 7)/8;
	rsa_req->q_len = (cop->crk_param[1].crp_nbits + 7)/8;
	rsa_req->g_len = (cop->crk_param[2].crp_nbits + 7)/8;
	rsa_req->dp_len = (cop->crk_param[3].crp_nbits + 7)/8;
	rsa_req->dq_len = (cop->crk_param[4].crp_nbits + 7)/8;
	rsa_req->c_len = (cop->crk_param[5].crp_nbits + 7)/8;
	rsa_req->f_len = (cop->crk_param[6].crp_nbits + 7)/8;
	buf = kmalloc(rsa_req->p_len + rsa_req->q_len + rsa_req->f_len +
		      rsa_req->dp_len + rsa_req->dp_len + rsa_req->c_len +
		      rsa_req->g_len, GFP_DMA);
	if (!buf)
		return -ENOMEM;
	rsa_req->p = buf;
	rsa_req->q = rsa_req->p + rsa_req->p_len;
	rsa_req->g = rsa_req->q + rsa_req->q_len;
	rsa_req->dp = rsa_req->g + rsa_req->g_len;
	rsa_req->dq = rsa_req->dp + rsa_req->dp_len;
	rsa_req->c = rsa_req->dq + rsa_req->dq_len;
	rsa_req->f = rsa_req->c + rsa_req->c_len;
	rc = copy_from_user(rsa_req->p, cop->crk_param[0].crp_p, rsa_req->p_len) ||
	     copy_from_user(rsa_req->q, cop->crk_param[1].crp_p, rsa_req->q_len) ||
	     copy_from_user(rsa_req->g, cop->crk_param[2].crp_p, rsa_req->g_len) ||
	     copy_from_user(rsa_req->dp, cop->crk_param[3].crp_p, rsa_req->dp_len) ||
	     copy_from_user(rsa_req->dq, cop->crk_param[4].crp_p, rsa_req->dq_len) ||
	     copy_from_user(rsa_req->c, cop->crk_param[5].crp_p, rsa_req->c_len);
	if (rc)
		goto err;

	rc = cryptodev_pkc_offload(pkc);

	if (pkc->type == SYNCHRONOUS) {
		rc = rc || copy_to_user(cop->crk_param[6].crp_p, rsa_req->f, rsa_req->f_len);
	} else {
		if (rc != -EINPROGRESS && rc != 0)
			goto err;

		pkc->cookie = buf;
		return rc;
	}
err:
	kfree(buf);
	return rc;
}

int crypto_bn_modexp(struct cryptodev_pkc *pkc)
{
	struct rsa_pub_req_s *rsa_req;
	int rc;
	struct kernel_crypt_kop *kop = &pkc->kop;
	struct crypt_kop *cop = &kop->kop;
	uint8_t *buf;

	if (!cop->crk_param[0].crp_nbits || !cop->crk_param[1].crp_nbits ||
	    !cop->crk_param[2].crp_nbits || !cop->crk_param[3].crp_nbits)
		return -EINVAL;

	rsa_req = &pkc->req->req_u.rsa_pub_req;
	rsa_req->f_len = (cop->crk_param[0].crp_nbits + 7)/8;
	rsa_req->e_len = (cop->crk_param[1].crp_nbits + 7)/8;
	rsa_req->n_len = (cop->crk_param[2].crp_nbits + 7)/8;
	rsa_req->g_len = (cop->crk_param[3].crp_nbits + 7)/8;
	buf = kmalloc(rsa_req->f_len + rsa_req->e_len + rsa_req->n_len
			+ rsa_req->g_len, GFP_DMA);
	if (!buf)
		return -ENOMEM;

	rsa_req->e = buf;
	rsa_req->f = rsa_req->e + rsa_req->e_len;
	rsa_req->g = rsa_req->f + rsa_req->f_len;
	rsa_req->n = rsa_req->g + rsa_req->g_len;
	rc = copy_from_user(rsa_req->f, cop->crk_param[0].crp_p, rsa_req->f_len) ||
	     copy_from_user(rsa_req->e, cop->crk_param[1].crp_p, rsa_req->e_len) ||
	     copy_from_user(rsa_req->n, cop->crk_param[2].crp_p, rsa_req->n_len);
	if (rc)
		goto err;

	rc = cryptodev_pkc_offload(pkc);
	if (pkc->type == SYNCHRONOUS) {
		rc = rc || copy_to_user(cop->crk_param[3].crp_p, rsa_req->g, rsa_req->g_len);
	} else {
		if (rc != -EINPROGRESS && rc != 0)
			goto err;

		/* This one will be freed later in fetch handler */
		pkc->cookie = buf;
		return rc;
	}
err:
	kfree(buf);
	return rc;
}

static struct {
	char *alg_name;
	u32 type;
	u32 mask;
} pkc_alg_list[] = {
		{"pkc(rsa)", CRYPTO_ALG_TYPE_PKC_RSA, 0},
		{"pkc(dsa)", CRYPTO_ALG_TYPE_PKC_DSA, 0},
		{"pkc(dh)", CRYPTO_ALG_TYPE_PKC_DH, 0},
};

int crypto_run_asym(struct cryptodev_pkc *pkc)
{
	int err = -EINVAL;
	int id;
	struct kernel_crypt_kop *kop = &pkc->kop;
	enum pkc_req_type pkc_req_type;
	int (*call_next_action)(struct cryptodev_pkc *pkc);

	switch (kop->kop.crk_op) {
	case CRK_MOD_EXP:
		if (kop->kop.crk_iparams != 3 && kop->kop.crk_oparams != 1)
			return err;
		pkc_req_type = RSA_PUB;
		id = 0;
		call_next_action = crypto_bn_modexp;
		break;
	case CRK_MOD_EXP_CRT:
		if (kop->kop.crk_iparams != 6 && kop->kop.crk_oparams != 1)
			return err;
		pkc_req_type = RSA_PRIV_FORM3;
		id = 0;
		call_next_action = crypto_modexp_crt;
		break;
	case CRK_DSA_SIGN:
		if (kop->kop.crk_oparams != 2)
			return err;
		else if (kop->kop.crk_iparams == 5)
			pkc_req_type = DSA_SIGN;
		else if (kop->kop.crk_iparams == 6)
			pkc_req_type = ECDSA_SIGN;
		else
			return err;
		id = 1;
		call_next_action = crypto_kop_dsasign;
		break;
	case CRK_DSA_VERIFY:
		if (kop->kop.crk_oparams != 0)
			return err;
		else if (kop->kop.crk_iparams == 7)
			pkc_req_type = DSA_VERIFY;
		else if (kop->kop.crk_iparams == 8)
			pkc_req_type = ECDSA_VERIFY;
		else
			return err;
		id = 1;
		call_next_action = crypto_kop_dsaverify;
		break;
	case CRK_DH_COMPUTE_KEY:
		if (kop->kop.crk_oparams != 1)
			return err;
		else if (kop->kop.crk_iparams == 3)
			pkc_req_type =  DH_COMPUTE_KEY;
		else if (kop->kop.crk_iparams == 4)
			pkc_req_type =  ECDH_COMPUTE_KEY;
		else
			return err;
		id = 2;
		call_next_action = crypto_kop_dh_key;
		break;
	case CRK_DH_GENERATE_KEY:
	case CRK_DSA_GENERATE_KEY:
		if (kop->kop.crk_iparams == 3)
			pkc_req_type = DLC_KEYGEN;
		else if (kop->kop.crk_iparams == 4)
			pkc_req_type = ECC_KEYGEN;
		else
			return err;
		id = 1;
		call_next_action = crypto_kop_keygen;
		break;
	case CRK_RSA_GENERATE_KEY:
		pkc_req_type = RSA_KEYGEN;
		id = 0;
		call_next_action = crypto_kop_rsa_keygen;
		break;
	default:
		return err;
	}
	err = -ENOMEM;
	pkc->s = crypto_alloc_pkc(pkc_alg_list[id].alg_name,
					pkc_alg_list[id].type,
					pkc_alg_list[id].mask);
	if (IS_ERR_OR_NULL(pkc->s))
		return err;

	pkc->req = pkc_request_alloc(pkc->s, GFP_KERNEL);
	if (IS_ERR_OR_NULL(pkc->req))
		goto out_free_tfm;

	/* todo - fix alloc-free on error path */
	pkc->req->type = pkc_req_type;
	err = call_next_action(pkc);
	if (pkc->type == SYNCHRONOUS)
		kfree(pkc->req);

	return err;

out_free_tfm:
	crypto_free_pkc(pkc->s);
	return err;
}

int crypto_run(struct fcrypt *fcr, struct kernel_crypt_op *kcop)
{
	struct csession *ses_ptr;
	struct crypt_op *cop = &kcop->cop;
	int ret;

	if (unlikely(cop->op != COP_ENCRYPT && cop->op != COP_DECRYPT)) {
		ddebug(1, "invalid operation op=%u", cop->op);
		return -EINVAL;
	}

	/* this also enters ses_ptr->sem */
	ses_ptr = crypto_get_session_by_sid(fcr, cop->ses);
	if (unlikely(!ses_ptr)) {
		derr(1, "invalid session ID=0x%08X", cop->ses);
		return -EINVAL;
	}

	if (ses_ptr->hdata.init != 0 && (cop->flags == 0 || cop->flags & COP_FLAG_RESET)) {
		ret = cryptodev_hash_reset(&ses_ptr->hdata);
		if (unlikely(ret)) {
			derr(1, "error in cryptodev_hash_reset()");
			goto out_unlock;
		}
	}

	if (ses_ptr->cdata.init != 0) {
		int blocksize = ses_ptr->cdata.blocksize;

		if (unlikely(cop->len % blocksize)) {
			derr(1, "data size (%u) isn't a multiple of block size (%u)",
				cop->len, blocksize);
			ret = -EINVAL;
			goto out_unlock;
		}

		cryptodev_cipher_set_iv(&ses_ptr->cdata, kcop->iv,
				min(ses_ptr->cdata.ivsize, kcop->ivlen));
	}

	if (likely(cop->len)) {
		if (cop->flags & COP_FLAG_NO_ZC) {
			if (unlikely(ses_ptr->alignmask && !IS_ALIGNED((unsigned long)cop->src, ses_ptr->alignmask))) {
				dwarning(2, "source address %p is not %d byte aligned - disabling zero copy",
						cop->src, ses_ptr->alignmask + 1);
				cop->flags &= ~COP_FLAG_NO_ZC;
			}

			if (unlikely(ses_ptr->alignmask && !IS_ALIGNED((unsigned long)cop->dst, ses_ptr->alignmask))) {
				dwarning(2, "destination address %p is not %d byte aligned - disabling zero copy",
						cop->dst, ses_ptr->alignmask + 1);
				cop->flags &= ~COP_FLAG_NO_ZC;
			}
		}

		if (cop->flags & COP_FLAG_NO_ZC)
			ret = __crypto_run_std(ses_ptr, &kcop->cop);
		else
			ret = __crypto_run_zc(ses_ptr, kcop);
		if (unlikely(ret))
			goto out_unlock;
	}

	if (ses_ptr->cdata.init != 0) {
		cryptodev_cipher_get_iv(&ses_ptr->cdata, kcop->iv,
				min(ses_ptr->cdata.ivsize, kcop->ivlen));
	}

	if (ses_ptr->hdata.init != 0 &&
		((cop->flags & COP_FLAG_FINAL) ||
		   (!(cop->flags & COP_FLAG_UPDATE) || cop->len == 0))) {

		ret = cryptodev_hash_final(&ses_ptr->hdata, kcop->hash_output);
		if (unlikely(ret)) {
			derr(0, "CryptoAPI failure: %d", ret);
			goto out_unlock;
		}
		kcop->digestsize = ses_ptr->hdata.digestsize;
	}

out_unlock:
	crypto_put_session(ses_ptr);
	return ret;
}
