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
package io.github.photowey.gmssl.core.constant;

/**
 * {@code GmSSL}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/06
 */
public interface GmSSLConstants {

    /**
     * GmSSL version
     */
    String GMSSL_VERSION = "v3.1.1";
    /**
     * 3.1.1: GmSSL version
     * 1.0.0: JNI version
     */
    String GMSSL_JNI_VERSION = "v3.1.1.1.0.0";

    interface SM2 {
        String SM2_DEFAULT_ID = "1234567812345678";
        int SM2_MAX_PLAINTEXT_SIZE = 255;
    }

    interface SM3 {
        int SM3_DIGEST_SIZE = 32;
        int SM3_HMAC_SIZE = 32;
        int SM3_HMAC_MIN_KEY_SIZE = 16;
        /**
         * from &lt;gmssl/pbkdf2.h&gt;
         */
        int SM3_PBKDF2_MIN_ITER = 10000;
        /**
         * 2^24
         */
        int SM3_PBKDF2_MAX_ITER = 16777216;
        /**
         * from &lt;gmssl/pbkdf2.h&gt;
         */
        int SM3_PBKDF2_MAX_SALT_SIZE = 64;
        /**
         * from &lt;gmssl/pbkdf2.h&gt;
         */
        int SM3_PBKDF2_DEFAULT_SALT_SIZE = 8;
        /**
         * from gmssljni.c:sm3_pbkdf2():sizeof(keybuf)
         */
        int SM3_PBKDF2_MAX_KEY_SIZE = 256;
    }

    interface SM4 {
        int SM4_KEY_SIZE = 16;
        int SM4_BLOCK_SIZE = 16;
        int SM4_CBC_IV_SIZE = 16;
        int SM4_CTR_IV_SIZE = 16;
        int SM4_GCM_MIN_IV_SIZE = 1;
        int SM4_GCM_MAX_IV_SIZE = 64;
        int SM4_GCM_DEFAULT_IV_SIZE = 12;
        int SM4_GCM_MAX_TAG_SIZE = 16;
    }

    interface SM9 {
        int SM9_MAX_PLAINTEXT_SIZE = 255;
    }

    interface ZUC {
        int ZUC_KEY_SIZE = 16;
        int ZUC_IV_SIZE = 16;
    }

}
