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
 * {@code Sm9SignMasterKey}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/10
 */
public class Sm9SignMasterKey {

    private long masterKey = 0;
    private boolean hasPrivateKey = false;

    public Sm9SignMasterKey() {
        this.masterKey = 0L;
    }

    public void generateMasterKey() {
        if (this.masterKey != 0) {
            GmSSLJNI.sm9_sign_master_key_free(this.masterKey);
        }
        this.masterKey = GmSSLJNI.sm9_sign_master_key_generate();
        if (this.masterKey == 0L) {
            throw new GmSSLException("gmssl: Generate SM9 sign master key failure.");
        }

        this.hasPrivateKey = true;
    }

    public long getMasterKey() {
        if (this.masterKey == 0L) {
            throw new GmSSLException("gmssl: Master key not initialized.");
        }
        if (!this.hasPrivateKey) {
            throw new GmSSLException("gmssl: Master key not initialized.");
        }

        return this.masterKey;
    }

    public long getPublicMasterKey() {
        if (this.masterKey == 0L) {
            throw new GmSSLException("gmssl: Master key not initialized.");
        }

        return this.masterKey;
    }

    public Sm9SignKey extractKey(String id) {
        if (this.masterKey == 0L) {
            throw new GmSSLException("gmssl: Master key not initialized.");
        }
        if (!this.hasPrivateKey) {
            throw new GmSSLException("gmssl: Master key not initialized.");
        }
        long key = GmSSLJNI.sm9_sign_master_key_extract_key(this.masterKey, id);
        if (key == 0L) {
            throw new GmSSLException("gmssl: Extract SM9 master key failure.");
        }

        return new Sm9SignKey(key, id);
    }

    public void importEncryptedMasterKeyInfoPem(String pass, String file) {
        if (this.masterKey != 0) {
            GmSSLJNI.sm9_sign_master_key_free(this.masterKey);
        }
        this.masterKey = GmSSLJNI.sm9_sign_master_key_info_decrypt_from_pem(pass, file);
        if (this.masterKey == 0L) {
            throw new GmSSLException("gmssl: Import SM9 master key failure.");
        }

        this.hasPrivateKey = true;
    }

    public void exportEncryptedMasterKeyInfoPem(String pass, String file) {
        if (this.masterKey == 0L) {
            throw new GmSSLException("gmssl: Master key not initialized.");
        }
        if (!this.hasPrivateKey) {
            throw new GmSSLException("gmssl: Master key not initialized.");
        }
        if (GmSSLJNI.sm9_sign_master_key_info_encrypt_to_pem(this.masterKey, pass, file) != 1) {
            throw new GmSSLException("gmssl: Export SM9 master key failure.");
        }
    }

    public void importPublicMasterKeyPem(String file) {
        if (this.masterKey != 0) {
            GmSSLJNI.sm9_sign_master_key_free(this.masterKey);
        }
        this.masterKey = GmSSLJNI.sm9_sign_master_public_key_from_pem(file);
        if (this.masterKey == 0L) {
            throw new GmSSLException("gmssl: Import SM9 public key failure.");
        }

        this.hasPrivateKey = false;
    }

    public void exportPublicMasterKeyPem(String file) {
        if (this.masterKey == 0L) {
            throw new GmSSLException("gmssl: Master key not initialized.");
        }
        if (GmSSLJNI.sm9_sign_master_public_key_to_pem(this.masterKey, file) != 1) {
            throw new GmSSLException("gmssl: Export SM9 public key failure.");
        }
    }
}
