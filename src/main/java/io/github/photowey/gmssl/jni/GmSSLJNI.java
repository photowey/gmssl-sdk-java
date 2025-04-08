/*
 * Copyright © 2025 the original author or authors.
 * Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.photowey.gmssl.jni;

import io.github.photowey.gmssl.core.loader.GmSSLNativeLoader;

/**
 * {@code GmSSLJNI}.
 * {@code GmSSL} C 库 {@code JNI} 绑定
 * ----------------------------------------------------------------
 * 与 [GmSSL-Java](https://github.com/GmSSL/GmSSL-Java) 设计不同点:
 * |- 1.将所有 {@code native} 方法定义为了 private 方法
 * |- 2.将所有 {@code native} 方法名定义为 {@code xxx0}
 * ----------------------------------------------------------------
 * $ javac -h . GmSSLJNI.java
 * ----------------------------------------------------------------
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/06
 */
public class GmSSLJNI {

    static {
        GmSSLNativeLoader.load(GmSSLNativeLoader.GMSSL_JNILIB_NAME);
    }

    public static String version_str() {
        return version_str0();
    }

    public static int version_num() {
        return version_num0();
    }

    public static int rand_bytes(byte[] buf, int offset, long nBytes) {
        return rand_bytes0(buf, offset, nBytes);
    }

    public static long sm3_ctx_new() {
        return sm3_ctx_new0();
    }

    public static void sm3_ctx_free(long sm3_ctx) {
        sm3_ctx_free0(sm3_ctx);
    }

    public static int sm3_init(long sm3_ctx) {
        return sm3_init0(sm3_ctx);
    }

    public static int sm3_update(long sm3_ctx, byte[] data, int offset, int dataLen) {
        return sm3_update0(sm3_ctx, data, offset, dataLen);
    }

    public static int sm3_finish(long sm3_ctx, byte[] digest) {
        return sm3_finish0(sm3_ctx, digest);
    }

    public static long sm3_hmac_ctx_new() {
        return sm3_hmac_ctx_new0();
    }

    public static void sm3_hmac_ctx_free(long sm3_hmac_ctx) {
        sm3_hmac_ctx_free0(sm3_hmac_ctx);
    }

    public static int sm3_hmac_init(long sm3_hmac_ctx, byte[] key) {
        return sm3_hmac_init0(sm3_hmac_ctx, key);
    }

    public static int sm3_hmac_update(long sm3_hmac_ctx, byte[] data, int offset, int dataLen) {
        return sm3_hmac_update0(sm3_hmac_ctx, data, offset, dataLen);
    }

    public static int sm3_hmac_finish(long sm3_hmac_ctx, byte[] hmac) {
        return sm3_hmac_finish0(sm3_hmac_ctx, hmac);
    }

    public static byte[] sm3_pbkdf2(String pass, byte[] salt, int iter, int keyLen) {
        return sm3_pbkdf20(pass, salt, iter, keyLen);
    }

    public static long sm4_key_new() {
        return sm4_key_new0();
    }

    public static void sm4_key_free(long sm4_key) {
        sm4_key_free0(sm4_key);
    }

    public static int sm4_set_encrypt_key(long sm4_key, byte[] key) {
        return sm4_set_encrypt_key0(sm4_key, key);
    }

    public static int sm4_set_decrypt_key(long sm4_key, byte[] key) {
        return sm4_set_decrypt_key0(sm4_key, key);
    }

    public static int sm4_encrypt(
        long sm4_key, byte[] in, int in_offset, byte[] out, int out_offset) {
        return sm4_encrypt0(sm4_key, in, in_offset, out, out_offset);
    }

    public static long sm4_cbc_ctx_new() {
        return sm4_cbc_ctx_new0();
    }

    public static void sm4_cbc_ctx_free(long sm4_cbc_ctx) {
        sm4_cbc_ctx_free0(sm4_cbc_ctx);
    }

    public static int sm4_cbc_encrypt_init(long sm4_cbc_ctx, byte[] key, byte[] iv) {
        return sm4_cbc_encrypt_init0(sm4_cbc_ctx, key, iv);
    }

    public static int sm4_cbc_encrypt_update(
        long sm4_cbc_ctx, byte[] in, int in_offset, int inLen, byte[] out, int out_offset) {
        return sm4_cbc_encrypt_update0(sm4_cbc_ctx, in, in_offset, inLen, out, out_offset);
    }

    public static int sm4_cbc_encrypt_finish(long sm4_cbc_ctx, byte[] out, int out_offset) {
        return sm4_cbc_encrypt_finish0(sm4_cbc_ctx, out, out_offset);
    }

    public static int sm4_cbc_decrypt_init(long sm4_cbc_ctx, byte[] key, byte[] iv) {
        return sm4_cbc_decrypt_init0(sm4_cbc_ctx, key, iv);
    }

    public static int sm4_cbc_decrypt_update(
        long sm4_cbc_ctx, byte[] in, int in_offset, int inLen, byte[] out, int out_offset) {
        return sm4_cbc_decrypt_update0(sm4_cbc_ctx, in, in_offset, inLen, out, out_offset);
    }

    public static int sm4_cbc_decrypt_finish(long sm4_cbc_ctx, byte[] out, int out_offset) {
        return sm4_cbc_decrypt_finish0(sm4_cbc_ctx, out, out_offset);
    }

    public static long sm4_ctr_ctx_new() {
        return sm4_ctr_ctx_new0();
    }

    public static void sm4_ctr_ctx_free(long sm4_ctr_ctx) {
        sm4_ctr_ctx_free0(sm4_ctr_ctx);
    }

    public static int sm4_ctr_encrypt_init(long sm4_ctr_ctx, byte[] key, byte[] iv) {
        return sm4_ctr_encrypt_init0(sm4_ctr_ctx, key, iv);
    }

    public static int sm4_ctr_encrypt_update(
        long sm4_ctr_ctx, byte[] in, int in_offset, int inLen, byte[] out, int out_offset) {
        return sm4_ctr_encrypt_update0(sm4_ctr_ctx, in, in_offset, inLen, out, out_offset);
    }

    public static int sm4_ctr_encrypt_finish(long sm4_ctr_ctx, byte[] out, int out_offset) {
        return sm4_ctr_encrypt_finish0(sm4_ctr_ctx, out, out_offset);
    }

    public static int sm4_ctr_decrypt_init(long sm4_ctr_ctx, byte[] key, byte[] iv) {
        return sm4_ctr_decrypt_init0(sm4_ctr_ctx, key, iv);
    }

    public static int sm4_ctr_decrypt_update(
        long sm4_ctr_ctx, byte[] in, int in_offset, int inLen, byte[] out, int out_offset) {
        return sm4_ctr_decrypt_update0(sm4_ctr_ctx, in, in_offset, inLen, out, out_offset);
    }

    public static int sm4_ctr_decrypt_finish(long sm4_ctr_ctx, byte[] out, int out_offset) {
        return sm4_ctr_decrypt_finish0(sm4_ctr_ctx, out, out_offset);
    }

    public static long sm4_gcm_ctx_new() {
        return sm4_gcm_ctx_new0();
    }

    public static void sm4_gcm_ctx_free(long sm4_gcm_ctx) {
        sm4_gcm_ctx_free0(sm4_gcm_ctx);
    }

    public static int sm4_gcm_encrypt_init(
        long sm4_gcm_ctx, byte[] key, byte[] iv, byte[] aad, int tagLen) {
        return sm4_gcm_encrypt_init0(sm4_gcm_ctx, key, iv, aad, tagLen);
    }

    public static int sm4_gcm_encrypt_update(
        long sm4_gcm_ctx, byte[] in, int in_offset, int inLen, byte[] out, int out_offset) {
        return sm4_gcm_encrypt_update0(sm4_gcm_ctx, in, in_offset, inLen, out, out_offset);
    }

    public static int sm4_gcm_encrypt_finish(
        long sm4_gcm_ctx, byte[] out, int out_offset) {
        return sm4_gcm_encrypt_finish0(sm4_gcm_ctx, out, out_offset);
    }

    public static int sm4_gcm_decrypt_init(
        long sm4_gcm_ctx, byte[] key, byte[] iv, byte[] aad, int tagLen) {
        return sm4_gcm_decrypt_init0(sm4_gcm_ctx, key, iv, aad, tagLen);
    }

    public static int sm4_gcm_decrypt_update(
        long sm4_gcm_ctx, byte[] in, int in_offset, int inLen, byte[] out, int out_offset) {
        return sm4_gcm_decrypt_update0(sm4_gcm_ctx, in, in_offset, inLen, out, out_offset);
    }

    public static int sm4_gcm_decrypt_finish(long sm4_gcm_ctx, byte[] out, int out_offset) {
        return sm4_gcm_decrypt_finish0(sm4_gcm_ctx, out, out_offset);
    }

    public static long zuc_ctx_new() {
        return zuc_ctx_new0();
    }

    public static void zuc_ctx_free(long zuc_ctx) {
        zuc_ctx_free0(zuc_ctx);
    }

    public static int zuc_encrypt_init(long zuc_ctx, byte[] key, byte[] iv) {
        return zuc_encrypt_init0(zuc_ctx, key, iv);
    }

    public static int zuc_encrypt_update(
        long zuc_ctx, byte[] in, int in_offset, int inLen, byte[] out, int out_offset) {
        return zuc_encrypt_update0(zuc_ctx, in, in_offset, inLen, out, out_offset);
    }

    public static int zuc_encrypt_finish(long zuc_ctx, byte[] out, int out_offset) {
        return zuc_encrypt_finish0(zuc_ctx, out, out_offset);
    }

    public static long sm2_key_generate() {
        return sm2_key_generate0();
    }

    public static void sm2_key_free(long sm2_key) {
        sm2_key_free0(sm2_key);
    }

    public static byte[] sm2_private_key_info_to_der(long sm2_key) {
        return sm2_private_key_info_to_der0(sm2_key);
    }

    public static long sm2_private_key_info_from_der(byte[] der) {
        return sm2_private_key_info_from_der0(der);
    }

    public static byte[] sm2_public_key_info_to_der(long sm2_key) {
        return sm2_public_key_info_to_der0(sm2_key);
    }

    public static long sm2_public_key_info_from_der(byte[] der) {
        return sm2_public_key_info_from_der0(der);
    }

    public static int sm2_private_key_info_encrypt_to_pem(long sm2_key, String pass, String file) {
        return sm2_private_key_info_encrypt_to_pem0(sm2_key, pass, file);
    }

    public static long sm2_private_key_info_decrypt_from_pem(String pass, String file) {
        return sm2_private_key_info_decrypt_from_pem0(pass, file);
    }

    public static int sm2_public_key_info_to_pem(long sm2_key, String file) {
        return sm2_public_key_info_to_pem0(sm2_key, file);
    }

    public static long sm2_public_key_info_from_pem(String file) {
        return sm2_public_key_info_from_pem0(file);
    }

    public static int sm2_compute_z(long sm2_key, String id, byte[] z) {
        return sm2_compute_z0(sm2_key, id, z);
    }

    public static byte[] sm2_sign(long sm2_key, byte[] digest) {
        return sm2_sign0(sm2_key, digest);
    }

    public static int sm2_verify(long sm2_key, byte[] digest, byte[] sign) {
        return sm2_verify0(sm2_key, digest, sign);
    }

    public static byte[] sm2_encrypt(long sm2_key, byte[] in) {
        return sm2_encrypt0(sm2_key, in);
    }

    public static byte[] sm2_decrypt(long sm2_key, byte[] in) {
        return sm2_decrypt0(sm2_key, in);
    }

    public static long sm2_sign_ctx_new() {
        return sm2_sign_ctx_new0();
    }

    public static void sm2_sign_ctx_free(long sm2_sign_ctx) {
        sm2_sign_ctx_free0(sm2_sign_ctx);
    }

    public static int sm2_sign_init(long sm2_sign_ctx, long sm2_key, String id) {
        return sm2_sign_init0(sm2_sign_ctx, sm2_key, id);
    }

    public static int sm2_sign_update(long sm2_sign_ctx, byte[] data, int offset, int length) {
        return sm2_sign_update0(sm2_sign_ctx, data, offset, length);
    }

    public static byte[] sm2_sign_finish(long sm2_sign_ctx) {
        return sm2_sign_finish0(sm2_sign_ctx);
    }

    public static int sm2_verify_init(long sm2_sign_ctx, long sm2_key, String id) {
        return sm2_verify_init0(sm2_sign_ctx, sm2_key, id);
    }

    public static int sm2_verify_update(long sm2_sign_ctx, byte[] data, int offset, int length) {
        return sm2_verify_update0(sm2_sign_ctx, data, offset, length);
    }

    public static int sm2_verify_finish(long sm2_sign_ctx, byte[] sign) {
        return sm2_verify_finish0(sm2_sign_ctx, sign);
    }

    public static long sm9_sign_master_key_generate() {
        return sm9_sign_master_key_generate0();
    }

    public static void sm9_sign_master_key_free(long sm9_sign_master_key) {
        sm9_sign_master_key_free0(sm9_sign_master_key);
    }

    public static int sm9_sign_master_key_info_encrypt_to_pem(
        long sm9_sign_master_key, String pass, String file) {
        return sm9_sign_master_key_info_encrypt_to_pem0(sm9_sign_master_key, pass, file);
    }

    public static long sm9_sign_master_key_info_decrypt_from_pem(String pass, String file) {
        return sm9_sign_master_key_info_decrypt_from_pem0(pass, file);
    }

    public static int sm9_sign_master_public_key_to_pem(long sm9_sign_master_pub, String file) {
        return sm9_sign_master_public_key_to_pem0(sm9_sign_master_pub, file);
    }

    public static long sm9_sign_master_public_key_from_pem(String file) {
        return sm9_sign_master_public_key_from_pem0(file);
    }

    public static long sm9_sign_master_key_extract_key(long sm9_sign_master_key, String id) {
        return sm9_sign_master_key_extract_key0(sm9_sign_master_key, id);
    }

    public static void sm9_sign_key_free(long sm9_sign_key) {
        sm9_sign_key_free0(sm9_sign_key);
    }

    public static int sm9_sign_key_info_encrypt_to_pem(
        long sm9_sign_key, String pass, String file) {
        return sm9_sign_key_info_encrypt_to_pem0(sm9_sign_key, pass, file);
    }

    public static long sm9_sign_key_info_decrypt_from_pem(String pass, String file) {
        return sm9_sign_key_info_decrypt_from_pem0(pass, file);
    }

    public static long sm9_sign_ctx_new() {
        return sm9_sign_ctx_new0();
    }

    public static void sm9_sign_ctx_free(long sm9_sign_ctx) {
        sm9_sign_ctx_free0(sm9_sign_ctx);
    }

    public static int sm9_sign_init(long sm9_sign_ctx) {
        return sm9_sign_init0(sm9_sign_ctx);
    }

    public static int sm9_sign_update(long sm9_sign_ctx, byte[] data, int offset, int length) {
        return sm9_sign_update0(sm9_sign_ctx, data, offset, length);
    }

    public static byte[] sm9_sign_finish(long sm9_sign_ctx, long sm9_sign_key) {
        return sm9_sign_finish0(sm9_sign_ctx, sm9_sign_key);
    }

    public static int sm9_verify_init(long sm9_sign_ctx) {
        return sm9_verify_init0(sm9_sign_ctx);
    }

    public static int sm9_verify_update(long sm9_sign_ctx, byte[] data, int offset, int length) {
        return sm9_verify_update0(sm9_sign_ctx, data, offset, length);
    }

    public static int sm9_verify_finish(
        long sm9_sign_ctx, byte[] sig, long sm9_sign_master_pub, String id) {
        return sm9_verify_finish0(sm9_sign_ctx, sig, sm9_sign_master_pub, id);
    }

    public static long sm9_enc_master_key_generate() {
        return sm9_enc_master_key_generate0();
    }

    public static void sm9_enc_master_key_free(long sm9_enc_master_key) {
        sm9_enc_master_key_free0(sm9_enc_master_key);
    }

    public static int sm9_enc_master_key_info_encrypt_to_pem(
        long sm9_enc_master_key, String pass, String file) {
        return sm9_enc_master_key_info_encrypt_to_pem0(sm9_enc_master_key, pass, file);
    }

    public static long sm9_enc_master_key_info_decrypt_from_pem(String pass, String file) {
        return sm9_enc_master_key_info_decrypt_from_pem0(pass, file);
    }

    public static int sm9_enc_master_public_key_to_pem(long sm9_enc_master_pub, String file) {
        return sm9_enc_master_public_key_to_pem0(sm9_enc_master_pub, file);
    }

    public static long sm9_enc_master_public_key_from_pem(String file) {
        return sm9_enc_master_public_key_from_pem0(file);
    }

    public static long sm9_enc_master_key_extract_key(long sm9_enc_master_key, String id) {
        return sm9_enc_master_key_extract_key0(sm9_enc_master_key, id);
    }

    public static void sm9_enc_key_free(long sm9_sign_key) {
        sm9_enc_key_free0(sm9_sign_key);
    }

    public static int sm9_enc_key_info_encrypt_to_pem(long sm9_enc_key, String pass, String file) {
        return sm9_enc_key_info_encrypt_to_pem0(sm9_enc_key, pass, file);
    }

    public static long sm9_enc_key_info_decrypt_from_pem(String pass, String file) {
        return sm9_enc_key_info_decrypt_from_pem0(pass, file);
    }

    public static byte[] sm9_encrypt(long sm9_enc_master_pub, String id, byte[] in) {
        return sm9_encrypt0(sm9_enc_master_pub, id, in);
    }

    public static byte[] sm9_decrypt(long sm9_enc_key, String id, byte[] in) {
        return sm9_decrypt0(sm9_enc_key, id, in);
    }

    public static byte[] cert_from_pem(String file) {
        return cert_from_pem0(file);
    }

    public static int cert_to_pem(byte[] cert, String file) {
        return cert_to_pem0(cert, file);
    }

    public static byte[] cert_get_serial_number(byte[] cert) {
        return cert_get_serial_number0(cert);
    }

    public static String[] cert_get_issuer(byte[] cert) {
        return cert_get_issuer0(cert);
    }

    public static String[] cert_get_subject(byte[] cert) {
        return cert_get_subject0(cert);
    }

    public static long cert_get_not_before(byte[] cert) {
        return cert_get_not_before0(cert);
    }

    public static long cert_get_not_after(byte[] cert) {
        return cert_get_not_after0(cert);
    }

    public static long cert_get_subject_public_key(byte[] cert) {
        return cert_get_subject_public_key0(cert);
    }

    public static int cert_verify_by_ca_cert(byte[] cert, byte[] caCert, String ca_sm2_id) {
        return cert_verify_by_ca_cert0(cert, caCert, ca_sm2_id);
    }

    // ----------------------------------------------------------------

    private static native String version_str0();

    private static native int version_num0();

    public static native int rand_bytes0(byte[] buf, int offset, long nBytes);

    public static native long sm3_ctx_new0();

    public static native void sm3_ctx_free0(long sm3_ctx);

    public static native int sm3_init0(long sm3_ctx);

    public static native int sm3_update0(long sm3_ctx, byte[] data, int offset, int dataLen);

    public static native int sm3_finish0(long sm3_ctx, byte[] digest);

    public static native long sm3_hmac_ctx_new0();

    public static native void sm3_hmac_ctx_free0(long sm3_hmac_ctx);

    public static native int sm3_hmac_init0(long sm3_hmac_ctx, byte[] key);

    public static native int sm3_hmac_update0(long sm3_hmac_ctx, byte[] data, int offset,
                                              int dataLen);

    public static native int sm3_hmac_finish0(long sm3_hmac_ctx, byte[] hmac);

    public static native byte[] sm3_pbkdf20(String pass, byte[] salt, int iter, int keyLen);

    public static native long sm4_key_new0();

    public static native void sm4_key_free0(long sm4_key);

    public static native int sm4_set_encrypt_key0(long sm4_key, byte[] key);

    public static native int sm4_set_decrypt_key0(long sm4_key, byte[] key);

    public static native int sm4_encrypt0(long sm4_key, byte[] in, int in_offset, byte[] out,
                                          int out_offset);

    public static native long sm4_cbc_ctx_new0();

    public static native void sm4_cbc_ctx_free0(long sm4_cbc_ctx);

    public static native int sm4_cbc_encrypt_init0(long sm4_cbc_ctx, byte[] key, byte[] iv);

    public static native int sm4_cbc_encrypt_update0(
        long sm4_cbc_ctx, byte[] in, int in_offset, int inLen, byte[] out, int out_offset);

    public static native int sm4_cbc_encrypt_finish0(long sm4_cbc_ctx, byte[] out, int out_offset);

    public static native int sm4_cbc_decrypt_init0(long sm4_cbc_ctx, byte[] key, byte[] iv);

    public static native int sm4_cbc_decrypt_update0(
        long sm4_cbc_ctx, byte[] in, int in_offset, int inLen, byte[] out, int out_offset);

    public static native int sm4_cbc_decrypt_finish0(long sm4_cbc_ctx, byte[] out, int out_offset);

    public static native long sm4_ctr_ctx_new0();

    public static native void sm4_ctr_ctx_free0(long sm4_ctr_ctx);

    public static native int sm4_ctr_encrypt_init0(long sm4_ctr_ctx, byte[] key, byte[] iv);

    public static native int sm4_ctr_encrypt_update0(
        long sm4_ctr_ctx, byte[] in, int in_offset, int inLen, byte[] out, int out_offset);

    public static native int sm4_ctr_encrypt_finish0(long sm4_ctr_ctx, byte[] out, int out_offset);

    public static native int sm4_ctr_decrypt_init0(long sm4_ctr_ctx, byte[] key, byte[] iv);

    public static native int sm4_ctr_decrypt_update0(
        long sm4_ctr_ctx, byte[] in, int in_offset, int inLen, byte[] out, int out_offset);

    public static native int sm4_ctr_decrypt_finish0(long sm4_ctr_ctx, byte[] out, int out_offset);

    public static native long sm4_gcm_ctx_new0();

    public static native void sm4_gcm_ctx_free0(long sm4_gcm_ctx);

    public static native int sm4_gcm_encrypt_init0(long sm4_gcm_ctx, byte[] key, byte[] iv,
                                                   byte[] aad, int tagLen);

    public static native int sm4_gcm_encrypt_update0(
        long sm4_gcm_ctx, byte[] in, int in_offset, int inLen, byte[] out, int out_offset);

    public static native int sm4_gcm_encrypt_finish0(long sm4_gcm_ctx, byte[] out, int out_offset);

    public static native int sm4_gcm_decrypt_init0(long sm4_gcm_ctx, byte[] key, byte[] iv,
                                                   byte[] aad, int tagLen);

    public static native int sm4_gcm_decrypt_update0(
        long sm4_gcm_ctx, byte[] in, int in_offset, int inLen, byte[] out, int out_offset);

    public static native int sm4_gcm_decrypt_finish0(long sm4_gcm_ctx, byte[] out, int out_offset);

    public static native long zuc_ctx_new0();

    public static native void zuc_ctx_free0(long zuc_ctx);

    public static native int zuc_encrypt_init0(long zuc_ctx, byte[] key, byte[] iv);

    public static native int zuc_encrypt_update0(
        long zuc_ctx, byte[] in, int in_offset, int inLen, byte[] out, int out_offset);

    public static native int zuc_encrypt_finish0(long zuc_ctx, byte[] out, int out_offset);

    public static native long sm2_key_generate0();

    public static native void sm2_key_free0(long sm2_key);

    public static native byte[] sm2_private_key_info_to_der0(long sm2_key);

    public static native long sm2_private_key_info_from_der0(byte[] der);

    public static native byte[] sm2_public_key_info_to_der0(long sm2_key);

    public static native long sm2_public_key_info_from_der0(byte[] der);

    public static native int sm2_private_key_info_encrypt_to_pem0(long sm2_key, String pass,
                                                                  String file);

    public static native long sm2_private_key_info_decrypt_from_pem0(String pass, String file);

    public static native int sm2_public_key_info_to_pem0(long sm2_key, String file);

    public static native long sm2_public_key_info_from_pem0(String file);

    public static native int sm2_compute_z0(long sm2_key, String id, byte[] z);

    public static native byte[] sm2_sign0(long sm2_key, byte[] digest);

    public static native int sm2_verify0(long sm2_key, byte[] digest, byte[] sign);

    public static native byte[] sm2_encrypt0(long sm2_key, byte[] in);

    public static native byte[] sm2_decrypt0(long sm2_key, byte[] in);

    public static native long sm2_sign_ctx_new0();

    public static native void sm2_sign_ctx_free0(long sm2_sign_ctx);

    public static native int sm2_sign_init0(long sm2_sign_ctx, long sm2_key, String id);

    public static native int sm2_sign_update0(long sm2_sign_ctx, byte[] data, int offset,
                                              int length);

    public static native byte[] sm2_sign_finish0(long sm2_sign_ctx);

    public static native int sm2_verify_init0(long sm2_sign_ctx, long sm2_key, String id);

    public static native int sm2_verify_update0(long sm2_sign_ctx, byte[] data, int offset,
                                                int length);

    public static native int sm2_verify_finish0(long sm2_sign_ctx, byte[] sign);

    public static native long sm9_sign_master_key_generate0();

    public static native void sm9_sign_master_key_free0(long sm9_sign_master_key);

    public static native int sm9_sign_master_key_info_encrypt_to_pem0(
        long sm9_sign_master_key, String pass, String file);

    public static native long sm9_sign_master_key_info_decrypt_from_pem0(String pass, String file);

    public static native int sm9_sign_master_public_key_to_pem0(long sm9_sign_master_pub,
                                                                String file);

    public static native long sm9_sign_master_public_key_from_pem0(String file);

    public static native long sm9_sign_master_key_extract_key0(long sm9_sign_master_key, String id);

    public static native void sm9_sign_key_free0(long sm9_sign_key);

    public static native int sm9_sign_key_info_encrypt_to_pem0(long sm9_sign_key, String pass,
                                                               String file);

    public static native long sm9_sign_key_info_decrypt_from_pem0(String pass, String file);

    public static native long sm9_sign_ctx_new0();

    public static native void sm9_sign_ctx_free0(long sm9_sign_ctx);

    public static native int sm9_sign_init0(long sm9_sign_ctx);

    public static native int sm9_sign_update0(long sm9_sign_ctx, byte[] data, int offset,
                                              int length);

    public static native byte[] sm9_sign_finish0(long sm9_sign_ctx, long sm9_sign_key);

    public static native int sm9_verify_init0(long sm9_sign_ctx);

    public static native int sm9_verify_update0(long sm9_sign_ctx, byte[] data, int offset,
                                                int length);

    public static native int sm9_verify_finish0(long sm9_sign_ctx, byte[] sig,
                                                long sm9_sign_master_pub, String id);

    public static native long sm9_enc_master_key_generate0();

    public static native void sm9_enc_master_key_free0(long sm9_enc_master_key);

    public static native int sm9_enc_master_key_info_encrypt_to_pem0(
        long sm9_enc_master_key, String pass, String file);

    public static native long sm9_enc_master_key_info_decrypt_from_pem0(String pass, String file);

    public static native int sm9_enc_master_public_key_to_pem0(long sm9_enc_master_pub,
                                                               String file);

    public static native long sm9_enc_master_public_key_from_pem0(String file);

    public static native long sm9_enc_master_key_extract_key0(long sm9_enc_master_key, String id);

    public static native void sm9_enc_key_free0(long sm9_sign_key);

    public static native int sm9_enc_key_info_encrypt_to_pem0(long sm9_enc_key, String pass,
                                                              String file);

    public static native long sm9_enc_key_info_decrypt_from_pem0(String pass, String file);

    public static native byte[] sm9_encrypt0(long sm9_enc_master_pub, String id, byte[] in);

    public static native byte[] sm9_decrypt0(long sm9_enc_key, String id, byte[] in);

    public static native byte[] cert_from_pem0(String file);

    public static native int cert_to_pem0(byte[] cert, String file);

    public static native byte[] cert_get_serial_number0(byte[] cert);

    public static native String[] cert_get_issuer0(byte[] cert);

    public static native String[] cert_get_subject0(byte[] cert);

    public static native long cert_get_not_before0(byte[] cert);

    public static native long cert_get_not_after0(byte[] cert);

    public static native long cert_get_subject_public_key0(byte[] cert);

    public static native int cert_verify_by_ca_cert0(byte[] cert, byte[] caCert, String ca_sm2_id);

}
