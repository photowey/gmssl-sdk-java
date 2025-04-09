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
 * {@code Sm9EncKey}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/10
 */
public class Sm9EncKey {

    private long key = 0;
    private String id;

    public Sm9EncKey(String id) {
        this(0L, id);
    }

    public Sm9EncKey(long key, String id) {
        this.key = key;
        this.id = id;
    }

    // ----------------------------------------------------------------

    public void importEncryptedPrivateKeyInfoPem(String password, String pem) {
        if (this.key != 0L) {
            GmSSLJNI.sm9_enc_key_free(this.key);
        }

        this.key = GmSSLJNI.sm9_enc_key_info_decrypt_from_pem(password, pem);
        if (this.key == 0L) {
            throw new GmSSLException("gmssl: Import private key failure.");
        }
    }

    public void exportEncryptedPrivateKeyInfoPem(String password, String pem) {
        if (this.key == 0L) {
            throw new GmSSLException("gmssl: Key not initialized.");
        }

        if (GmSSLJNI.sm9_enc_key_info_encrypt_to_pem(this.key, password, pem) != 1) {
            throw new GmSSLException("gmssl: Export private key failure.");
        }
    }

    // ----------------------------------------------------------------

    public byte[] decrypt(byte[] cipherBytes) {
        if (this.key == 0L) {
            throw new GmSSLException("gmssl: Key not initialized.");
        }

        if (cipherBytes == null) {
            throw new GmSSLException("gmssl: SM9 decrypt cipher can't be null.");
        }

        byte[] decryptedBytes = GmSSLJNI.sm9_decrypt(this.key, this.id, cipherBytes);
        if (decryptedBytes == null) {
            throw new GmSSLException("gmssl: SM9 decrypt failure.");
        }

        return decryptedBytes;
    }

    // ----------------------------------------------------------------

    public String id() {
        return this.id;
    }

}
