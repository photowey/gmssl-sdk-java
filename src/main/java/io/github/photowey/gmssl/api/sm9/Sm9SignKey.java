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
package io.github.photowey.gmssl.api.sm9;

import io.github.photowey.gmssl.core.exception.GmSSLException;
import io.github.photowey.gmssl.jni.GmSSLJNI;

/**
 * {@code Sm9SignKey}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/10
 */
public class Sm9SignKey {

    private long signKey = 0;
    private String id;

    public Sm9SignKey(String id) {
        this(0L, id);
    }

    public Sm9SignKey(long key, String id) {
        this.signKey = key;
        this.id = id;
    }

    public long getKey() {
        if (this.signKey == 0L) {
            throw new GmSSLException("gmssl: Key not initialized.");
        }

        return this.signKey;
    }

    public void exportEncryptedPrivateKeyInfoPem(String password, String pem) {
        if (this.signKey == 0) {
            throw new GmSSLException("gmssl: Key not initialized.");
        }

        if (GmSSLJNI.sm9_sign_key_info_encrypt_to_pem(this.signKey, password, pem) != 1) {
            throw new GmSSLException("gmssl: Export SM9 private key failure.");
        }
    }

    public void importEncryptedPrivateKeyInfoPem(String password, String pem) {
        if (this.signKey != 0) {
            GmSSLJNI.sm9_sign_key_free(this.signKey);
        }

        this.signKey = GmSSLJNI.sm9_sign_key_info_decrypt_from_pem(password, pem);
        if (this.signKey == 0) {
            throw new GmSSLException("gmssl: Import SM9 private key failure.");
        }
    }

    // ----------------------------------------------------------------

    public String id() {
        return this.id;
    }
}
