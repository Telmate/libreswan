/*
 * PRF helper functions, for libreswan
 *
 * Copyright (C) 2007-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <stdlib.h>

//#include "libreswan.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "crypt_prf.h"
#include "crypto.h"

/* MUST BE THREAD-SAFE */
PK11SymKey *skeyid_digisig(const chunk_t ni,
			   const chunk_t nr,
			   /*const*/ PK11SymKey *shared,	/* NSS doesn't do const */
			   const struct hash_desc *hasher)
{
	struct hmac_ctx ctx;
	chunk_t nir;
	unsigned int k;
	CK_MECHANISM_TYPE mechanism;
	u_char buf1[HMAC_BUFSIZE * 2], buf2[HMAC_BUFSIZE * 2];
	chunk_t buf1_chunk, buf2_chunk;
	PK11SymKey *skeyid;

	DBG(DBG_CRYPT, {
		    DBG_log("skeyid inputs (digi+NI+NR+shared) hasher: %s",
			    hasher->common.name);
		    DBG_dump_chunk("ni: ", ni);
		    DBG_dump_chunk("nr: ", nr);
	    });

	/*
	 * We need to hmac_init with the concatenation of Ni_b and Nr_b,
	 * so we have to build a temporary concatentation.
	 */
	nir.len = ni.len + nr.len;
	nir.ptr = alloc_bytes(nir.len, "Ni + Nr in skeyid_digisig");
	memcpy(nir.ptr, ni.ptr, ni.len);
	memcpy(nir.ptr + ni.len, nr.ptr, nr.len);
	zero(&buf1);
	if (nir.len <= hasher->hash_block_size) {
		memcpy(buf1, nir.ptr, nir.len);
	} else {
		hasher->hash_init(&ctx.hash_ctx);
		hasher->hash_update(&ctx.hash_ctx, nir.ptr, nir.len);
		hasher->hash_final(buf1, &ctx.hash_ctx);
	}

	memcpy(buf2, buf1, hasher->hash_block_size);

	for (k = 0; k < hasher->hash_block_size; k++) {
		buf1[k] ^= HMAC_IPAD;
		buf2[k] ^= HMAC_OPAD;
	}

	pfree(nir.ptr);
	mechanism = nss_key_derivation_mech(hasher);
	buf1_chunk.ptr = buf1;
	buf1_chunk.len = hasher->hash_block_size;

	buf2_chunk.ptr = buf2;
	buf2_chunk.len = hasher->hash_block_size;

	PK11SymKey *tkey1 = pk11_derive_wrapper_lsw(shared,
						    CKM_CONCATENATE_DATA_AND_BASE, buf1_chunk, mechanism, CKA_DERIVE,
						    0);
	PK11SymKey *tkey2 = PK11_Derive_lsw(tkey1, mechanism, NULL,
					    CKM_CONCATENATE_DATA_AND_BASE,
					    CKA_DERIVE, 0);
	PK11SymKey *tkey3 = pk11_derive_wrapper_lsw(tkey2,
						    CKM_CONCATENATE_DATA_AND_BASE, buf2_chunk, mechanism, CKA_DERIVE,
						    0);
	skeyid = PK11_Derive_lsw(tkey3, mechanism, NULL,
				 CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, 0);

	PK11_FreeSymKey(tkey1);
	PK11_FreeSymKey(tkey2);
	PK11_FreeSymKey(tkey3);

	DBG(DBG_CRYPT,
	    DBG_log("NSS: digisig skeyid pointer: %p", skeyid));

	return skeyid;
}

static PK11SymKey *key_from_key_bits(PK11SymKey *base_key,
				     CK_MECHANISM_TYPE target,
				     CK_FLAGS flags,
				     size_t next_bit, size_t key_size)
{
	/* spell out all the parameters */
	CK_EXTRACT_PARAMS bs = next_bit;
	SECItem param = {
		.data = (unsigned char*)&bs,
		.len = sizeof(bs),
	};
	CK_MECHANISM_TYPE derive = CKM_EXTRACT_KEY_FROM_KEY;
	CK_ATTRIBUTE_TYPE operation = CKA_FLAGS_ONLY;
	return PK11_DeriveWithFlags(base_key, derive, &param,
				    target, operation, key_size, flags);
}

/*
 * Extract SIZEOF_CHUNK bytes, starting at bit NEXT_BIT, from SOURCE_KEY.
 */
chunk_t chunk_from_symkey_bits(const char *name, PK11SymKey *source_key,
			       size_t next_bit, size_t sizeof_chunk)
{
	if (sizeof_chunk == 0) {
		DBG(DBG_CRYPT, DBG_log("chunk_from_symkey: %s: zero size", name));
		return empty_chunk;
	}
	PK11SymKey *sym_key = key_from_key_bits(source_key,
						CKM_VENDOR_DEFINED, 0,
						next_bit, sizeof_chunk);
	if (sym_key == NULL) {
		loglog(RC_LOG_SERIOUS, "NSS: PK11_DeriveWithFlags failed while generating %s", name);
		return empty_chunk;
	}
	SECStatus s = PK11_ExtractKeyValue(sym_key);
	if (s != SECSuccess) {
		loglog(RC_LOG_SERIOUS, "NSS: PK11_ExtractKeyValue failed while generating %s", name);
		return empty_chunk;
	}
	/* Internal structure address, do not free.  */
	SECItem *data = PK11_GetKeyData(sym_key);
	if (data == NULL) {
		loglog(RC_LOG_SERIOUS, "NSS: PK11_GetKeyData failed while generating %s", name);
		return empty_chunk;
	}
	DBG(DBG_CRYPT,
	    DBG_log("chunk_from_symkey: %s: extracted len %d bytes at %p",
		    name, data->len, data->data));
	if (data->len != sizeof_chunk) {
		loglog(RC_LOG_SERIOUS, "NSS: PK11_GetKeyData returned wrong number of bytes while generating %s", name);
		return empty_chunk;
	}
	chunk_t chunk;
	clonetochunk(chunk, data->data, data->len, name);
	DBG(DBG_CRYPT, DBG_dump_chunk(name, chunk));
	PK11_FreeSymKey(sym_key);
	return chunk;
}

/*
 * Extract SIZEOF_CHUNK bytes, starting at byte NEXT_BYTE, from SOURCE_KEY.
 */
chunk_t chunk_from_symkey_bytes(const char *name, PK11SymKey *source_key,
				size_t next_byte, size_t sizeof_chunk)
{
	return chunk_from_symkey_bits(name, source_key,
				      next_byte * BITS_PER_BYTE, sizeof_chunk);
}

PK11SymKey *encrypt_key_from_symkey_bits(PK11SymKey *source_key,
					 const struct encrypt_desc *encrypter,
					 size_t next_bit, size_t sizeof_symkey)
{
	return key_from_key_bits(source_key,
				 nss_encryption_mech(encrypter),
				 CKF_ENCRYPT | CKF_DECRYPT,
				 next_bit, sizeof_symkey);
}

PK11SymKey *encrypt_key_from_symkey_bytes(PK11SymKey *source_key,
					  const struct encrypt_desc *encrypter,
					  size_t next_byte, size_t sizeof_symkey)
{
	return encrypt_key_from_symkey_bits(source_key, encrypter,
					    next_byte * BITS_PER_BYTE,
					    sizeof_symkey);
}

/*
 * Extract key that doesn't need to support encryption.
 */
PK11SymKey *key_from_symkey_bits(PK11SymKey *base_key,
				 size_t next_bit, int key_size)
{				    
	CK_EXTRACT_PARAMS bs = next_bit;
	SECItem param = {
		.data = (unsigned char*)&bs,
		.len = sizeof(bs),
	};
	CK_MECHANISM_TYPE derive = CKM_EXTRACT_KEY_FROM_KEY;
	CK_MECHANISM_TYPE target = CKM_CONCATENATE_BASE_AND_DATA;
	CK_ATTRIBUTE_TYPE operation = CKA_DERIVE;
	/* XXX: can this use key_from_key_bits? */
	return PK11_Derive(base_key, derive, &param, target,
			   operation, key_size);
}

PK11SymKey *key_from_symkey_bytes(PK11SymKey *source_key,
				  size_t next_byte, int sizeof_key)
{
	return key_from_symkey_bits(source_key, next_byte, sizeof_key);
}
