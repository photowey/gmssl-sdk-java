/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class io_github_photowey_gmssl_jni_GmSSLJNI */

#ifndef _Included_io_github_photowey_gmssl_jni_GmSSLJNI
#define _Included_io_github_photowey_gmssl_jni_GmSSLJNI
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    version_str0
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_version_1str0
  (JNIEnv *, jclass);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    version_num0
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_version_1num0
  (JNIEnv *, jclass);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    rand_bytes0
 * Signature: ([BIJ)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_rand_1bytes0
  (JNIEnv *, jclass, jbyteArray, jint, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm3_ctx_new0
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm3_1ctx_1new0
  (JNIEnv *, jclass);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm3_ctx_free0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm3_1ctx_1free0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm3_init0
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm3_1init0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm3_update0
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm3_1update0
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm3_finish0
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm3_1finish0
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm3_hmac_ctx_new0
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm3_1hmac_1ctx_1new0
  (JNIEnv *, jclass);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm3_hmac_ctx_free0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm3_1hmac_1ctx_1free0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm3_hmac_init0
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm3_1hmac_1init0
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm3_hmac_update0
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm3_1hmac_1update0
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm3_hmac_finish0
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm3_1hmac_1finish0
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm3_pbkdf20
 * Signature: (Ljava/lang/String;[BII)[B
 */
JNIEXPORT jbyteArray JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm3_1pbkdf20
  (JNIEnv *, jclass, jstring, jbyteArray, jint, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_key_new0
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1key_1new0
  (JNIEnv *, jclass);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_key_free0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1key_1free0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_set_encrypt_key0
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1set_1encrypt_1key0
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_set_decrypt_key0
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1set_1decrypt_1key0
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_encrypt0
 * Signature: (J[BI[BI)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1encrypt0
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jbyteArray, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_cbc_ctx_new0
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1cbc_1ctx_1new0
  (JNIEnv *, jclass);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_cbc_ctx_free0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1cbc_1ctx_1free0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_cbc_encrypt_init0
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1cbc_1encrypt_1init0
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_cbc_encrypt_update0
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1cbc_1encrypt_1update0
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint, jbyteArray, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_cbc_encrypt_finish0
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1cbc_1encrypt_1finish0
  (JNIEnv *, jclass, jlong, jbyteArray, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_cbc_decrypt_init0
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1cbc_1decrypt_1init0
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_cbc_decrypt_update0
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1cbc_1decrypt_1update0
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint, jbyteArray, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_cbc_decrypt_finish0
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1cbc_1decrypt_1finish0
  (JNIEnv *, jclass, jlong, jbyteArray, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_ctr_ctx_new0
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1ctr_1ctx_1new0
  (JNIEnv *, jclass);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_ctr_ctx_free0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1ctr_1ctx_1free0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_ctr_encrypt_init0
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1ctr_1encrypt_1init0
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_ctr_encrypt_update0
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1ctr_1encrypt_1update0
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint, jbyteArray, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_ctr_encrypt_finish0
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1ctr_1encrypt_1finish0
  (JNIEnv *, jclass, jlong, jbyteArray, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_ctr_decrypt_init0
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1ctr_1decrypt_1init0
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_ctr_decrypt_update0
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1ctr_1decrypt_1update0
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint, jbyteArray, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_ctr_decrypt_finish0
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1ctr_1decrypt_1finish0
  (JNIEnv *, jclass, jlong, jbyteArray, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_gcm_ctx_new0
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1gcm_1ctx_1new0
  (JNIEnv *, jclass);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_gcm_ctx_free0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1gcm_1ctx_1free0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_gcm_encrypt_init0
 * Signature: (J[B[B[BI)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1gcm_1encrypt_1init0
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray, jbyteArray, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_gcm_encrypt_update0
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1gcm_1encrypt_1update0
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint, jbyteArray, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_gcm_encrypt_finish0
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1gcm_1encrypt_1finish0
  (JNIEnv *, jclass, jlong, jbyteArray, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_gcm_decrypt_init0
 * Signature: (J[B[B[BI)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1gcm_1decrypt_1init0
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray, jbyteArray, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_gcm_decrypt_update0
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1gcm_1decrypt_1update0
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint, jbyteArray, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm4_gcm_decrypt_finish0
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm4_1gcm_1decrypt_1finish0
  (JNIEnv *, jclass, jlong, jbyteArray, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    zuc_ctx_new0
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_zuc_1ctx_1new0
  (JNIEnv *, jclass);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    zuc_ctx_free0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_zuc_1ctx_1free0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    zuc_encrypt_init0
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_zuc_1encrypt_1init0
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    zuc_encrypt_update0
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_zuc_1encrypt_1update0
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint, jbyteArray, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    zuc_encrypt_finish0
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_zuc_1encrypt_1finish0
  (JNIEnv *, jclass, jlong, jbyteArray, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_key_generate0
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1key_1generate0
  (JNIEnv *, jclass);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_key_free0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1key_1free0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_private_key_info_to_der0
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1private_1key_1info_1to_1der0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_private_key_info_from_der0
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1private_1key_1info_1from_1der0
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_public_key_info_to_der0
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1public_1key_1info_1to_1der0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_public_key_info_from_der0
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1public_1key_1info_1from_1der0
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_private_key_info_encrypt_to_pem0
 * Signature: (JLjava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1private_1key_1info_1encrypt_1to_1pem0
  (JNIEnv *, jclass, jlong, jstring, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_private_key_info_decrypt_from_pem0
 * Signature: (Ljava/lang/String;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1private_1key_1info_1decrypt_1from_1pem0
  (JNIEnv *, jclass, jstring, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_public_key_info_to_pem0
 * Signature: (JLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1public_1key_1info_1to_1pem0
  (JNIEnv *, jclass, jlong, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_public_key_info_from_pem0
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1public_1key_1info_1from_1pem0
  (JNIEnv *, jclass, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_compute_z0
 * Signature: (JLjava/lang/String;[B)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1compute_1z0
  (JNIEnv *, jclass, jlong, jstring, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_sign0
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1sign0
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_verify0
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1verify0
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_encrypt0
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1encrypt0
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_decrypt0
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1decrypt0
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_sign_ctx_new0
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1sign_1ctx_1new0
  (JNIEnv *, jclass);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_sign_ctx_free0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1sign_1ctx_1free0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_sign_init0
 * Signature: (JJLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1sign_1init0
  (JNIEnv *, jclass, jlong, jlong, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_sign_update0
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1sign_1update0
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_sign_finish0
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1sign_1finish0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_verify_init0
 * Signature: (JJLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1verify_1init0
  (JNIEnv *, jclass, jlong, jlong, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_verify_update0
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1verify_1update0
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm2_verify_finish0
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm2_1verify_1finish0
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_sign_master_key_generate0
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1sign_1master_1key_1generate0
  (JNIEnv *, jclass);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_sign_master_key_free0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1sign_1master_1key_1free0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_sign_master_key_info_encrypt_to_pem0
 * Signature: (JLjava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1sign_1master_1key_1info_1encrypt_1to_1pem0
  (JNIEnv *, jclass, jlong, jstring, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_sign_master_key_info_decrypt_from_pem0
 * Signature: (Ljava/lang/String;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1sign_1master_1key_1info_1decrypt_1from_1pem0
  (JNIEnv *, jclass, jstring, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_sign_master_public_key_to_pem0
 * Signature: (JLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1sign_1master_1public_1key_1to_1pem0
  (JNIEnv *, jclass, jlong, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_sign_master_public_key_from_pem0
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1sign_1master_1public_1key_1from_1pem0
  (JNIEnv *, jclass, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_sign_master_key_extract_key0
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1sign_1master_1key_1extract_1key0
  (JNIEnv *, jclass, jlong, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_sign_key_free0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1sign_1key_1free0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_sign_key_info_encrypt_to_pem0
 * Signature: (JLjava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1sign_1key_1info_1encrypt_1to_1pem0
  (JNIEnv *, jclass, jlong, jstring, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_sign_key_info_decrypt_from_pem0
 * Signature: (Ljava/lang/String;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1sign_1key_1info_1decrypt_1from_1pem0
  (JNIEnv *, jclass, jstring, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_sign_ctx_new0
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1sign_1ctx_1new0
  (JNIEnv *, jclass);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_sign_ctx_free0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1sign_1ctx_1free0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_sign_init0
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1sign_1init0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_sign_update0
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1sign_1update0
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_sign_finish0
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1sign_1finish0
  (JNIEnv *, jclass, jlong, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_verify_init0
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1verify_1init0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_verify_update0
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1verify_1update0
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_verify_finish0
 * Signature: (J[BJLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1verify_1finish0
  (JNIEnv *, jclass, jlong, jbyteArray, jlong, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_enc_master_key_generate0
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1enc_1master_1key_1generate0
  (JNIEnv *, jclass);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_enc_master_key_free0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1enc_1master_1key_1free0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_enc_master_key_info_encrypt_to_pem0
 * Signature: (JLjava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1enc_1master_1key_1info_1encrypt_1to_1pem0
  (JNIEnv *, jclass, jlong, jstring, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_enc_master_key_info_decrypt_from_pem0
 * Signature: (Ljava/lang/String;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1enc_1master_1key_1info_1decrypt_1from_1pem0
  (JNIEnv *, jclass, jstring, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_enc_master_public_key_to_pem0
 * Signature: (JLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1enc_1master_1public_1key_1to_1pem0
  (JNIEnv *, jclass, jlong, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_enc_master_public_key_from_pem0
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1enc_1master_1public_1key_1from_1pem0
  (JNIEnv *, jclass, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_enc_master_key_extract_key0
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1enc_1master_1key_1extract_1key0
  (JNIEnv *, jclass, jlong, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_enc_key_free0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1enc_1key_1free0
  (JNIEnv *, jclass, jlong);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_enc_key_info_encrypt_to_pem0
 * Signature: (JLjava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1enc_1key_1info_1encrypt_1to_1pem0
  (JNIEnv *, jclass, jlong, jstring, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_enc_key_info_decrypt_from_pem0
 * Signature: (Ljava/lang/String;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1enc_1key_1info_1decrypt_1from_1pem0
  (JNIEnv *, jclass, jstring, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_encrypt0
 * Signature: (JLjava/lang/String;[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1encrypt0
  (JNIEnv *, jclass, jlong, jstring, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    sm9_decrypt0
 * Signature: (JLjava/lang/String;[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_sm9_1decrypt0
  (JNIEnv *, jclass, jlong, jstring, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    cert_from_pem0
 * Signature: (Ljava/lang/String;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_cert_1from_1pem0
  (JNIEnv *, jclass, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    cert_to_pem0
 * Signature: ([BLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_cert_1to_1pem0
  (JNIEnv *, jclass, jbyteArray, jstring);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    cert_get_serial_number0
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_cert_1get_1serial_1number0
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    cert_get_issuer0
 * Signature: ([B)[Ljava/lang/String;
 */
JNIEXPORT jobjectArray JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_cert_1get_1issuer0
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    cert_get_subject0
 * Signature: ([B)[Ljava/lang/String;
 */
JNIEXPORT jobjectArray JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_cert_1get_1subject0
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    cert_get_not_before0
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_cert_1get_1not_1before0
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    cert_get_not_after0
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_cert_1get_1not_1after0
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    cert_get_subject_public_key0
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_cert_1get_1subject_1public_1key0
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     io_github_photowey_gmssl_jni_GmSSLJNI
 * Method:    cert_verify_by_ca_cert0
 * Signature: ([B[BLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_io_github_photowey_gmssl_jni_GmSSLJNI_cert_1verify_1by_1ca_1cert0
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jstring);

#ifdef __cplusplus
}
#endif
#endif
