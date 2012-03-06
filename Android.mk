LOCAL_PATH := $(call my-dir)

SSHDROID_CFLAGS := -DSSHDROID_DROPBEAR_PATH='"/data/data/berserker.android.apps.sshdroid/dropbear"'
SSHDROIDPRO_CFLAGS := -DSSHDROID_DROPBEAR_PATH='"/data/data/berserker.android.apps.sshdroidpro/dropbear"'

#############################################################

# Libreria libtommath

include $(CLEAR_VARS)

LOCAL_MODULE := libtommath

LOCAL_SRC_FILES :=\
	dropbear/libtommath/bncore.c\
	dropbear/libtommath/bn_mp_init.c\
	dropbear/libtommath/bn_mp_clear.c\
	dropbear/libtommath/bn_mp_exch.c\
	dropbear/libtommath/bn_mp_grow.c\
	dropbear/libtommath/bn_mp_shrink.c\
	dropbear/libtommath/bn_mp_clamp.c\
	dropbear/libtommath/bn_mp_zero.c\
	dropbear/libtommath/bn_mp_set.c\
	dropbear/libtommath/bn_mp_set_int.c\
	dropbear/libtommath/bn_mp_init_size.c\
	dropbear/libtommath/bn_mp_copy.c\
	dropbear/libtommath/bn_mp_init_copy.c\
	dropbear/libtommath/bn_mp_abs.c\
	dropbear/libtommath/bn_mp_neg.c\
	dropbear/libtommath/bn_mp_cmp_mag.c\
	dropbear/libtommath/bn_mp_cmp.c\
	dropbear/libtommath/bn_mp_cmp_d.c\
	dropbear/libtommath/bn_mp_rshd.c\
	dropbear/libtommath/bn_mp_lshd.c\
	dropbear/libtommath/bn_mp_mod_2d.c\
	dropbear/libtommath/bn_mp_div_2d.c\
	dropbear/libtommath/bn_mp_mul_2d.c\
	dropbear/libtommath/bn_mp_div_2.c\
	dropbear/libtommath/bn_mp_mul_2.c\
	dropbear/libtommath/bn_s_mp_add.c\
	dropbear/libtommath/bn_s_mp_sub.c\
	dropbear/libtommath/bn_fast_s_mp_mul_digs.c\
	dropbear/libtommath/bn_s_mp_mul_digs.c\
	dropbear/libtommath/bn_fast_s_mp_mul_high_digs.c\
	dropbear/libtommath/bn_s_mp_mul_high_digs.c\
	dropbear/libtommath/bn_fast_s_mp_sqr.c\
	dropbear/libtommath/bn_s_mp_sqr.c\
	dropbear/libtommath/bn_mp_add.c\
	dropbear/libtommath/bn_mp_sub.c\
	dropbear/libtommath/bn_mp_karatsuba_mul.c\
	dropbear/libtommath/bn_mp_mul.c\
	dropbear/libtommath/bn_mp_karatsuba_sqr.c\
	dropbear/libtommath/bn_mp_sqr.c\
	dropbear/libtommath/bn_mp_div.c\
	dropbear/libtommath/bn_mp_mod.c\
	dropbear/libtommath/bn_mp_add_d.c\
	dropbear/libtommath/bn_mp_sub_d.c\
	dropbear/libtommath/bn_mp_mul_d.c\
	dropbear/libtommath/bn_mp_div_d.c\
	dropbear/libtommath/bn_mp_mod_d.c\
	dropbear/libtommath/bn_mp_expt_d.c\
	dropbear/libtommath/bn_mp_addmod.c\
	dropbear/libtommath/bn_mp_submod.c\
	dropbear/libtommath/bn_mp_mulmod.c\
	dropbear/libtommath/bn_mp_sqrmod.c\
	dropbear/libtommath/bn_mp_gcd.c\
	dropbear/libtommath/bn_mp_lcm.c\
	dropbear/libtommath/bn_fast_mp_invmod.c\
	dropbear/libtommath/bn_mp_invmod.c\
	dropbear/libtommath/bn_mp_reduce.c\
	dropbear/libtommath/bn_mp_montgomery_setup.c\
	dropbear/libtommath/bn_fast_mp_montgomery_reduce.c\
	dropbear/libtommath/bn_mp_montgomery_reduce.c\
	dropbear/libtommath/bn_mp_exptmod_fast.c\
	dropbear/libtommath/bn_mp_exptmod.c\
	dropbear/libtommath/bn_mp_2expt.c\
	dropbear/libtommath/bn_mp_n_root.c\
	dropbear/libtommath/bn_mp_jacobi.c\
	dropbear/libtommath/bn_reverse.c\
	dropbear/libtommath/bn_mp_count_bits.c\
	dropbear/libtommath/bn_mp_read_unsigned_bin.c\
	dropbear/libtommath/bn_mp_read_signed_bin.c\
	dropbear/libtommath/bn_mp_to_unsigned_bin.c\
	dropbear/libtommath/bn_mp_to_signed_bin.c\
	dropbear/libtommath/bn_mp_unsigned_bin_size.c\
	dropbear/libtommath/bn_mp_signed_bin_size.c\
	dropbear/libtommath/bn_mp_xor.c\
	dropbear/libtommath/bn_mp_and.c\
	dropbear/libtommath/bn_mp_or.c\
	dropbear/libtommath/bn_mp_rand.c\
	dropbear/libtommath/bn_mp_montgomery_calc_normalization.c\
	dropbear/libtommath/bn_mp_prime_is_divisible.c\
	dropbear/libtommath/bn_prime_tab.c\
	dropbear/libtommath/bn_mp_prime_fermat.c\
	dropbear/libtommath/bn_mp_prime_miller_rabin.c\
	dropbear/libtommath/bn_mp_prime_is_prime.c\
	dropbear/libtommath/bn_mp_prime_next_prime.c\
	dropbear/libtommath/bn_mp_dr_reduce.c\
	dropbear/libtommath/bn_mp_dr_is_modulus.c\
	dropbear/libtommath/bn_mp_dr_setup.c\
	dropbear/libtommath/bn_mp_reduce_setup.c\
	dropbear/libtommath/bn_mp_toom_mul.c\
	dropbear/libtommath/bn_mp_toom_sqr.c\
	dropbear/libtommath/bn_mp_div_3.c\
	dropbear/libtommath/bn_s_mp_exptmod.c\
	dropbear/libtommath/bn_mp_reduce_2k.c\
	dropbear/libtommath/bn_mp_reduce_is_2k.c\
	dropbear/libtommath/bn_mp_reduce_2k_setup.c\
	dropbear/libtommath/bn_mp_reduce_2k_l.c\
	dropbear/libtommath/bn_mp_reduce_is_2k_l.c\
	dropbear/libtommath/bn_mp_reduce_2k_setup_l.c\
	dropbear/libtommath/bn_mp_radix_smap.c\
	dropbear/libtommath/bn_mp_read_radix.c\
	dropbear/libtommath/bn_mp_toradix.c\
	dropbear/libtommath/bn_mp_radix_size.c\
	dropbear/libtommath/bn_mp_fread.c\
	dropbear/libtommath/bn_mp_fwrite.c\
	dropbear/libtommath/bn_mp_cnt_lsb.c\
	dropbear/libtommath/bn_error.c\
	dropbear/libtommath/bn_mp_init_multi.c\
	dropbear/libtommath/bn_mp_clear_multi.c\
	dropbear/libtommath/bn_mp_exteuclid.c\
	dropbear/libtommath/bn_mp_toradix_n.c\
	dropbear/libtommath/bn_mp_prime_random_ex.c\
	dropbear/libtommath/bn_mp_get_int.c\
	dropbear/libtommath/bn_mp_sqrt.c\
	dropbear/libtommath/bn_mp_is_square.c\
	dropbear/libtommath/bn_mp_init_set.c\
	dropbear/libtommath/bn_mp_init_set_int.c\
	dropbear/libtommath/bn_mp_invmod_slow.c\
	dropbear/libtommath/bn_mp_prime_rabin_miller_trials.c\
	dropbear/libtommath/bn_mp_to_signed_bin_n.c\
	dropbear/libtommath/bn_mp_to_unsigned_bin_n.c

LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear/libtommath

include $(BUILD_STATIC_LIBRARY)

#############################################################

# Libreria libtomcrypt

include $(CLEAR_VARS)

LOCAL_MODULE := libtomcrypt

LOCAL_SRC_FILES :=\
	dropbear/libtomcrypt/src/ciphers/aes/aes.c\
	dropbear/libtomcrypt/src/ciphers/anubis.c\
	dropbear/libtomcrypt/src/ciphers/blowfish.c\
	dropbear/libtomcrypt/src/ciphers/cast5.c\
	dropbear/libtomcrypt/src/ciphers/des.c\
	dropbear/libtomcrypt/src/ciphers/kasumi.c\
	dropbear/libtomcrypt/src/ciphers/khazad.c\
	dropbear/libtomcrypt/src/ciphers/kseed.c\
	dropbear/libtomcrypt/src/ciphers/noekeon.c\
	dropbear/libtomcrypt/src/ciphers/rc2.c\
	dropbear/libtomcrypt/src/ciphers/rc5.c\
	dropbear/libtomcrypt/src/ciphers/rc6.c\
	dropbear/libtomcrypt/src/ciphers/safer/safer.c\
	dropbear/libtomcrypt/src/ciphers/safer/safer_tab.c\
	dropbear/libtomcrypt/src/ciphers/safer/saferp.c\
	dropbear/libtomcrypt/src/ciphers/skipjack.c\
	dropbear/libtomcrypt/src/ciphers/twofish/twofish.c\
	dropbear/libtomcrypt/src/ciphers/xtea.c\
	dropbear/libtomcrypt/src/encauth/ccm/ccm_memory.c\
	dropbear/libtomcrypt/src/encauth/ccm/ccm_test.c\
	dropbear/libtomcrypt/src/encauth/eax/eax_addheader.c\
	dropbear/libtomcrypt/src/encauth/eax/eax_decrypt.c\
	dropbear/libtomcrypt/src/encauth/eax/eax_decrypt_verify_memory.c\
	dropbear/libtomcrypt/src/encauth/eax/eax_done.c\
	dropbear/libtomcrypt/src/encauth/eax/eax_encrypt.c\
	dropbear/libtomcrypt/src/encauth/eax/eax_encrypt_authenticate_memory.c\
	dropbear/libtomcrypt/src/encauth/eax/eax_init.c\
	dropbear/libtomcrypt/src/encauth/eax/eax_test.c\
	dropbear/libtomcrypt/src/encauth/gcm/gcm_add_aad.c\
	dropbear/libtomcrypt/src/encauth/gcm/gcm_add_iv.c\
	dropbear/libtomcrypt/src/encauth/gcm/gcm_done.c\
	dropbear/libtomcrypt/src/encauth/gcm/gcm_gf_mult.c\
	dropbear/libtomcrypt/src/encauth/gcm/gcm_init.c\
	dropbear/libtomcrypt/src/encauth/gcm/gcm_memory.c\
	dropbear/libtomcrypt/src/encauth/gcm/gcm_mult_h.c\
	dropbear/libtomcrypt/src/encauth/gcm/gcm_process.c\
	dropbear/libtomcrypt/src/encauth/gcm/gcm_reset.c\
	dropbear/libtomcrypt/src/encauth/gcm/gcm_test.c\
	dropbear/libtomcrypt/src/encauth/ocb/ocb_decrypt.c\
	dropbear/libtomcrypt/src/encauth/ocb/ocb_decrypt_verify_memory.c\
	dropbear/libtomcrypt/src/encauth/ocb/ocb_done_decrypt.c\
	dropbear/libtomcrypt/src/encauth/ocb/ocb_done_encrypt.c\
	dropbear/libtomcrypt/src/encauth/ocb/ocb_encrypt.c\
	dropbear/libtomcrypt/src/encauth/ocb/ocb_encrypt_authenticate_memory.c\
	dropbear/libtomcrypt/src/encauth/ocb/ocb_init.c\
	dropbear/libtomcrypt/src/encauth/ocb/ocb_ntz.c\
	dropbear/libtomcrypt/src/encauth/ocb/ocb_shift_xor.c\
	dropbear/libtomcrypt/src/encauth/ocb/ocb_test.c\
	dropbear/libtomcrypt/src/encauth/ocb/s_ocb_done.c\
	dropbear/libtomcrypt/src/hashes/chc/chc.c\
	dropbear/libtomcrypt/src/hashes/helper/hash_file.c\
	dropbear/libtomcrypt/src/hashes/helper/hash_filehandle.c\
	dropbear/libtomcrypt/src/hashes/helper/hash_memory.c\
	dropbear/libtomcrypt/src/hashes/helper/hash_memory_multi.c\
	dropbear/libtomcrypt/src/hashes/md2.c\
	dropbear/libtomcrypt/src/hashes/md4.c\
	dropbear/libtomcrypt/src/hashes/md5.c\
	dropbear/libtomcrypt/src/hashes/rmd128.c\
	dropbear/libtomcrypt/src/hashes/rmd160.c\
	dropbear/libtomcrypt/src/hashes/rmd256.c\
	dropbear/libtomcrypt/src/hashes/rmd320.c\
	dropbear/libtomcrypt/src/hashes/sha1.c\
	dropbear/libtomcrypt/src/hashes/sha2/sha256.c\
	dropbear/libtomcrypt/src/hashes/sha2/sha512.c\
	dropbear/libtomcrypt/src/hashes/tiger.c\
	dropbear/libtomcrypt/src/hashes/whirl/whirl.c\
	dropbear/libtomcrypt/src/mac/f9/f9_done.c\
	dropbear/libtomcrypt/src/mac/f9/f9_file.c\
	dropbear/libtomcrypt/src/mac/f9/f9_init.c\
	dropbear/libtomcrypt/src/mac/f9/f9_memory.c\
	dropbear/libtomcrypt/src/mac/f9/f9_memory_multi.c\
	dropbear/libtomcrypt/src/mac/f9/f9_process.c\
	dropbear/libtomcrypt/src/mac/f9/f9_test.c\
	dropbear/libtomcrypt/src/mac/hmac/hmac_done.c\
	dropbear/libtomcrypt/src/mac/hmac/hmac_file.c\
	dropbear/libtomcrypt/src/mac/hmac/hmac_init.c\
	dropbear/libtomcrypt/src/mac/hmac/hmac_memory.c\
	dropbear/libtomcrypt/src/mac/hmac/hmac_memory_multi.c\
	dropbear/libtomcrypt/src/mac/hmac/hmac_process.c\
	dropbear/libtomcrypt/src/mac/hmac/hmac_test.c\
	dropbear/libtomcrypt/src/mac/omac/omac_done.c\
	dropbear/libtomcrypt/src/mac/omac/omac_file.c\
	dropbear/libtomcrypt/src/mac/omac/omac_init.c\
	dropbear/libtomcrypt/src/mac/omac/omac_memory.c\
	dropbear/libtomcrypt/src/mac/omac/omac_memory_multi.c\
	dropbear/libtomcrypt/src/mac/omac/omac_process.c\
	dropbear/libtomcrypt/src/mac/omac/omac_test.c\
	dropbear/libtomcrypt/src/mac/pelican/pelican.c\
	dropbear/libtomcrypt/src/mac/pelican/pelican_memory.c\
	dropbear/libtomcrypt/src/mac/pelican/pelican_test.c\
	dropbear/libtomcrypt/src/mac/pmac/pmac_done.c\
	dropbear/libtomcrypt/src/mac/pmac/pmac_file.c\
	dropbear/libtomcrypt/src/mac/pmac/pmac_init.c\
	dropbear/libtomcrypt/src/mac/pmac/pmac_memory.c\
	dropbear/libtomcrypt/src/mac/pmac/pmac_memory_multi.c\
	dropbear/libtomcrypt/src/mac/pmac/pmac_ntz.c\
	dropbear/libtomcrypt/src/mac/pmac/pmac_process.c\
	dropbear/libtomcrypt/src/mac/pmac/pmac_shift_xor.c\
	dropbear/libtomcrypt/src/mac/pmac/pmac_test.c\
	dropbear/libtomcrypt/src/mac/xcbc/xcbc_done.c\
	dropbear/libtomcrypt/src/mac/xcbc/xcbc_file.c\
	dropbear/libtomcrypt/src/mac/xcbc/xcbc_init.c\
	dropbear/libtomcrypt/src/mac/xcbc/xcbc_memory.c\
	dropbear/libtomcrypt/src/mac/xcbc/xcbc_memory_multi.c\
	dropbear/libtomcrypt/src/mac/xcbc/xcbc_process.c\
	dropbear/libtomcrypt/src/mac/xcbc/xcbc_test.c\
	dropbear/libtomcrypt/src/math/fp/ltc_ecc_fp_mulmod.c\
	dropbear/libtomcrypt/src/math/gmp_desc.c\
	dropbear/libtomcrypt/src/math/ltm_desc.c\
	dropbear/libtomcrypt/src/math/multi.c\
	dropbear/libtomcrypt/src/math/rand_prime.c\
	dropbear/libtomcrypt/src/math/tfm_desc.c\
	dropbear/libtomcrypt/src/misc/base64/base64_decode.c\
	dropbear/libtomcrypt/src/misc/base64/base64_encode.c\
	dropbear/libtomcrypt/src/misc/burn_stack.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_argchk.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_cipher_descriptor.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_cipher_is_valid.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_find_cipher.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_find_cipher_any.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_find_cipher_id.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_find_hash.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_find_hash_any.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_find_hash_id.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_find_hash_oid.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_find_prng.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_fsa.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_hash_descriptor.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_hash_is_valid.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_ltc_mp_descriptor.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_prng_descriptor.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_prng_is_valid.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_register_cipher.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_register_hash.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_register_prng.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_unregister_cipher.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_unregister_hash.c\
	dropbear/libtomcrypt/src/misc/crypt/crypt_unregister_prng.c\
	dropbear/libtomcrypt/src/misc/error_to_string.c\
	dropbear/libtomcrypt/src/misc/pkcs5/pkcs_5_1.c\
	dropbear/libtomcrypt/src/misc/pkcs5/pkcs_5_2.c\
	dropbear/libtomcrypt/src/misc/zeromem.c\
	dropbear/libtomcrypt/src/modes/cbc/cbc_decrypt.c\
	dropbear/libtomcrypt/src/modes/cbc/cbc_done.c\
	dropbear/libtomcrypt/src/modes/cbc/cbc_encrypt.c\
	dropbear/libtomcrypt/src/modes/cbc/cbc_getiv.c\
	dropbear/libtomcrypt/src/modes/cbc/cbc_setiv.c\
	dropbear/libtomcrypt/src/modes/cbc/cbc_start.c\
	dropbear/libtomcrypt/src/modes/cfb/cfb_decrypt.c\
	dropbear/libtomcrypt/src/modes/cfb/cfb_done.c\
	dropbear/libtomcrypt/src/modes/cfb/cfb_encrypt.c\
	dropbear/libtomcrypt/src/modes/cfb/cfb_getiv.c\
	dropbear/libtomcrypt/src/modes/cfb/cfb_setiv.c\
	dropbear/libtomcrypt/src/modes/cfb/cfb_start.c\
	dropbear/libtomcrypt/src/modes/ctr/ctr_decrypt.c\
	dropbear/libtomcrypt/src/modes/ctr/ctr_done.c\
	dropbear/libtomcrypt/src/modes/ctr/ctr_encrypt.c\
	dropbear/libtomcrypt/src/modes/ctr/ctr_getiv.c\
	dropbear/libtomcrypt/src/modes/ctr/ctr_setiv.c\
	dropbear/libtomcrypt/src/modes/ctr/ctr_start.c\
	dropbear/libtomcrypt/src/modes/ctr/ctr_test.c\
	dropbear/libtomcrypt/src/modes/ecb/ecb_decrypt.c\
	dropbear/libtomcrypt/src/modes/ecb/ecb_done.c\
	dropbear/libtomcrypt/src/modes/ecb/ecb_encrypt.c\
	dropbear/libtomcrypt/src/modes/ecb/ecb_start.c\
	dropbear/libtomcrypt/src/modes/f8/f8_decrypt.c\
	dropbear/libtomcrypt/src/modes/f8/f8_done.c\
	dropbear/libtomcrypt/src/modes/f8/f8_encrypt.c\
	dropbear/libtomcrypt/src/modes/f8/f8_getiv.c\
	dropbear/libtomcrypt/src/modes/f8/f8_setiv.c\
	dropbear/libtomcrypt/src/modes/f8/f8_start.c\
	dropbear/libtomcrypt/src/modes/f8/f8_test_mode.c\
	dropbear/libtomcrypt/src/modes/lrw/lrw_decrypt.c\
	dropbear/libtomcrypt/src/modes/lrw/lrw_done.c\
	dropbear/libtomcrypt/src/modes/lrw/lrw_encrypt.c\
	dropbear/libtomcrypt/src/modes/lrw/lrw_getiv.c\
	dropbear/libtomcrypt/src/modes/lrw/lrw_process.c\
	dropbear/libtomcrypt/src/modes/lrw/lrw_setiv.c\
	dropbear/libtomcrypt/src/modes/lrw/lrw_start.c\
	dropbear/libtomcrypt/src/modes/lrw/lrw_test.c\
	dropbear/libtomcrypt/src/modes/ofb/ofb_decrypt.c\
	dropbear/libtomcrypt/src/modes/ofb/ofb_done.c\
	dropbear/libtomcrypt/src/modes/ofb/ofb_encrypt.c\
	dropbear/libtomcrypt/src/modes/ofb/ofb_getiv.c\
	dropbear/libtomcrypt/src/modes/ofb/ofb_setiv.c\
	dropbear/libtomcrypt/src/modes/ofb/ofb_start.c

LOCAL_CFLAGS += -DDROPBEAR_CLIENT

LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear/libtomcrypt/src/headers

include $(BUILD_STATIC_LIBRARY)

#############################################################

# Eseguibile ssh

include $(CLEAR_VARS)

LOCAL_MODULE := ssh

LOCAL_SRC_FILES :=\
	dropbear/dbutil.c\
	dropbear/buffer.c\
	dropbear/dss.c\
	dropbear/bignum.c\
	dropbear/signkey.c\
	dropbear/rsa.c\
	dropbear/random.c\
	dropbear/queue.c\
	dropbear/atomicio.c\
	dropbear/compat.c\
	dropbear/fake-rfc2553.c\
	dropbear/cli-agentfwd.c\
	dropbear/common-session.c\
	dropbear/packet.c\
	dropbear/common-algo.c\
	dropbear/common-kex.c\
	dropbear/common-channel.c\
	dropbear/common-chansession.c\
	dropbear/termcodes.c\
	dropbear/tcp-accept.c\
	dropbear/list.c\
	dropbear/listener.c\
	dropbear/process-packet.c\
	dropbear/common-runopts.c\
	dropbear/circbuffer.c\
	dropbear/cli-algo.c\
	dropbear/cli-main.c\
	dropbear/cli-auth.c\
	dropbear/cli-authpasswd.c\
	dropbear/cli-kex.c\
	dropbear/cli-session.c\
	dropbear/cli-service.c\
	dropbear/cli-runopts.c\
	dropbear/cli-chansession.c\
	dropbear/cli-authpubkey.c\
	dropbear/cli-tcpfwd.c\
	dropbear/cli-channel.c\
	dropbear/cli-authinteract.c\
	dropbear/netbsd_getpass.c

LOCAL_CFLAGS += -DDROPBEAR_CLIENT

LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear/libtommath
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear/libtomcrypt/src/headers

LOCAL_STATIC_LIBRARIES := libtommath libtomcrypt

include $(BUILD_EXECUTABLE)

#############################################################

# Eseguibile dropbearkey

include $(CLEAR_VARS)

LOCAL_MODULE := dropbearkey

LOCAL_SRC_FILES :=\
	dropbear/dbutil.c\
	dropbear/buffer.c\
	dropbear/dss.c\
	dropbear/bignum.c\
	dropbear/signkey.c\
	dropbear/rsa.c\
	dropbear/random.c\
	dropbear/queue.c\
	dropbear/atomicio.c\
	dropbear/compat.c\
	dropbear/fake-rfc2553.c\
	dropbear/dropbearkey.c\
	dropbear/gendss.c\
	dropbear/genrsa.c

LOCAL_CFLAGS += -DDROPBEAR_SERVER

LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear/libtommath
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear/libtomcrypt/src/headers

LOCAL_STATIC_LIBRARIES := libtommath libtomcrypt

include $(BUILD_EXECUTABLE)

#############################################################

# Eseguibile sftp-server

include $(CLEAR_VARS)

LOCAL_MODULE := sftp-server

LOCAL_SRC_FILES :=\
	dropbear/sftp-server/sftp-server.c\
	dropbear/sftp-server/sftp-common.c\
	dropbear/sftp-server/sftp-server-main.c\
	dropbear/sftp-server/addrmatch.c\
	dropbear/sftp-server/bufaux.c\
	dropbear/sftp-server/buffer.c\
	dropbear/sftp-server/compat.c\
	dropbear/sftp-server/log.c\
	dropbear/sftp-server/openbsd-compat/bsd-misc.c\
	dropbear/sftp-server/openbsd-compat/bsd-statvfs.c\
	dropbear/sftp-server/openbsd-compat/fmt_scaled.c\
	dropbear/sftp-server/openbsd-compat/getopt.c\
	dropbear/sftp-server/openbsd-compat/port-tun.c\
	dropbear/sftp-server/openbsd-compat/pwcache.c\
	dropbear/sftp-server/openbsd-compat/strmode.c\
	dropbear/sftp-server/openbsd-compat/strtonum.c\
	dropbear/sftp-server/openbsd-compat/vis.c\
	dropbear/sftp-server/match.c\
	dropbear/sftp-server/misc.c\
	dropbear/sftp-server/xmalloc.c

LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear/sftp-server

include $(BUILD_EXECUTABLE)

#############################################################

# Eseguibile scp (parte comune free/pro)

SCP_SRC_FILES :=\
	dropbear/scp.c\
	dropbear/progressmeter.c\
	dropbear/atomicio.c\
	dropbear/scpmisc.c

#############################################################

# Eseguibile scp_free

include $(CLEAR_VARS)

LOCAL_MODULE := scp_free

LOCAL_SRC_FILES := $(SCP_SRC_FILES)

LOCAL_CFLAGS += -DDROPBEAR_CLIENT -DPROGRESS_METER
LOCAL_CFLAGS += $(SSHDROID_CFLAGS)

LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear/libtommath
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear/libtomcrypt/src/headers

LOCAL_STATIC_LIBRARIES := libtommath libtomcrypt

include $(BUILD_EXECUTABLE)

#############################################################

# Eseguibile scp_pro

include $(CLEAR_VARS)

LOCAL_MODULE := scp_pro

LOCAL_SRC_FILES := $(SCP_SRC_FILES)

LOCAL_CFLAGS += -DDROPBEAR_CLIENT -DPROGRESS_METER
LOCAL_CFLAGS += $(SSHDROIDPRO_CFLAGS)

LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear/libtommath
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear/libtomcrypt/src/headers

LOCAL_STATIC_LIBRARIES := libtommath libtomcrypt

include $(BUILD_EXECUTABLE)

#############################################################

# Eseguibile dropbear (parte comune free/pro)

DROPBEAR_SRC_FILES :=\
	dropbear/dbutil.c\
	dropbear/buffer.c\
	dropbear/dss.c\
	dropbear/bignum.c\
	dropbear/signkey.c\
	dropbear/rsa.c\
	dropbear/random.c\
	dropbear/queue.c\
	dropbear/atomicio.c\
	dropbear/compat.c\
	dropbear/fake-rfc2553.c\
	dropbear/common-session.c\
	dropbear/packet.c\
	dropbear/common-algo.c\
	dropbear/common-kex.c\
	dropbear/common-channel.c\
	dropbear/common-chansession.c\
	dropbear/termcodes.c\
	dropbear/tcp-accept.c\
	dropbear/listener.c\
	dropbear/process-packet.c\
	dropbear/common-runopts.c\
	dropbear/circbuffer.c\
	dropbear/loginrec.c\
	dropbear/svr-kex.c\
	dropbear/svr-algo.c\
	dropbear/svr-auth.c\
	dropbear/sshpty.c\
	dropbear/svr-authpasswd.c\
	dropbear/svr-authpubkey.c\
	dropbear/svr-authpubkeyoptions.c\
	dropbear/svr-session.c\
	dropbear/svr-service.c\
	dropbear/svr-chansession.c\
	dropbear/svr-runopts.c\
	dropbear/svr-agentfwd.c\
	dropbear/svr-main.c\
	dropbear/svr-x11fwd.c\
	dropbear/svr-tcpfwd.c\
	dropbear/svr-authpam.c
	
SRC_FILES_THIRDPARTY :=\
	include/crypt.c\
	include/des.c\
	include/md5.c

DROPBEAR_SRC_FILES += $(SRC_FILES_THIRDPARTY)

#############################################################

# Eseguibile dropbear_free

include $(CLEAR_VARS)

LOCAL_MODULE := dropbear_free

LOCAL_SRC_FILES := $(DROPBEAR_SRC_FILES)

LOCAL_CFLAGS += -DDROPBEAR_SERVER -DANDROID_CHANGES
LOCAL_CFLAGS += $(SSHDROID_CFLAGS)

LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear/libtommath
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear/libtomcrypt/src/headers

LOCAL_STATIC_LIBRARIES := libtommath libtomcrypt

include $(BUILD_EXECUTABLE)

#############################################################

# Eseguibile dropbear_pro

include $(CLEAR_VARS)

LOCAL_MODULE := dropbear_pro

LOCAL_SRC_FILES := $(DROPBEAR_SRC_FILES)

LOCAL_CFLAGS += -DDROPBEAR_SERVER -DANDROID_CHANGES
LOCAL_CFLAGS += $(SSHDROIDPRO_CFLAGS)

LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear/libtommath
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear/libtomcrypt/src/headers

LOCAL_STATIC_LIBRARIES := libtommath libtomcrypt

include $(BUILD_EXECUTABLE)

#############################################################

# Eseguibile dropbearconvert

include $(CLEAR_VARS)

LOCAL_MODULE := dropbearconvert

LOCAL_SRC_FILES :=\
	dropbear/bignum.c\
	dropbear/buffer.c\
	dropbear/dbutil.c\
	dropbear/dss.c\
	dropbear/dropbearconvert.c\
	dropbear/keyimport.c\
	dropbear/rsa.c\
	dropbear/signkey.c

LOCAL_CFLAGS += -DDROPBEAR_SERVER

LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear/libtommath
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dropbear/libtomcrypt/src/headers

LOCAL_STATIC_LIBRARIES := libtommath libtomcrypt

include $(BUILD_EXECUTABLE)
