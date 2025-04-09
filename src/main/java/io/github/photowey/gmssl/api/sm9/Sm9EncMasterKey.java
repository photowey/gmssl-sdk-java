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

import io.github.photowey.gmssl.core.constant.GmSSLConstants;
import io.github.photowey.gmssl.core.exception.GmSSLException;
import io.github.photowey.gmssl.jni.GmSSLJNI;

/**
 * {@code Sm9EncMasterKey}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/10
 */
public class Sm9EncMasterKey {

    public final static int MAX_PLAINTEXT_SIZE = GmSSLConstants.SM9.SM9_MAX_PLAINTEXT_SIZE;

    private long masterKey = 0;
    private boolean hasPrivateKey = false;

    public Sm9EncMasterKey() {
        this.masterKey = 0;
    }

    public void generateMasterKey() {
        if ( this.masterKey != 0L) {
            GmSSLJNI.sm9_enc_master_key_free(this.masterKey);
        }

        this.masterKey = GmSSLJNI.sm9_enc_master_key_generate();
        if (this.masterKey == 0L) {
            throw new GmSSLException("gmssl: Generate SM9 master key failure.");
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

    public Sm9EncKey extractKey(String id) {
        if (this.masterKey == 0L) {
            throw new GmSSLException("gmssl: Master key not initialized.");
        }

        if (!this.hasPrivateKey) {
            throw new GmSSLException("gmssl: Master key not initialized.");
        }

        long key = GmSSLJNI.sm9_enc_master_key_extract_key(this.masterKey, id);
        if (0L == key) {
            throw new GmSSLException("gmssl: Extract SM9 master key failure.");
        }

        return new Sm9EncKey(key, id);
    }

    public void importEncryptedMasterKeyInfoPem(String password, String pem) {
        if ( this.masterKey != 0L) {
            GmSSLJNI.sm9_enc_master_key_free(this.masterKey);
        }

        this.masterKey = GmSSLJNI.sm9_enc_master_key_info_decrypt_from_pem(password, pem);
        if (this.masterKey == 0) {
            throw new GmSSLException("gmssl: Import private key failure.");
        }

        this.hasPrivateKey = true;
    }

    public void exportEncryptedMasterKeyInfoPem(String password, String pem) {
        if (this.masterKey == 0L) {
            throw new GmSSLException("gmssl: Key not initialized.");
        }
        if (!this.hasPrivateKey) {
            throw new GmSSLException("gmssl: Master key not initialized.");
        }
        if (GmSSLJNI.sm9_enc_master_key_info_encrypt_to_pem(this.masterKey, password, pem) != 1) {
            throw new GmSSLException("gmssl: Extract SM9 master key failure.");
        }
    }

    public void importPublicMasterKeyPem(String file) {
        if ( this.masterKey != 0L) {
            GmSSLJNI.sm9_enc_master_key_free(this.masterKey);
        }

        this.masterKey = GmSSLJNI.sm9_enc_master_public_key_from_pem(file);
        if (this.masterKey == 0L) {
            throw new GmSSLException("gmssl: Import private key failure.");
        }

        this.hasPrivateKey = false;
    }

    public void exportPublicMasterKeyPem(String file) {
        if (this.masterKey == 0L) {
            throw new GmSSLException("gmssl: Key not initialized.");
        }
        if (GmSSLJNI.sm9_enc_master_public_key_to_pem(this.masterKey, file) != 1) {
            throw new GmSSLException("gmssl: Extract SM9 master key failure.");
        }
    }

    public byte[] encrypt(byte[] dataBytes, String id) {
        if (this.masterKey == 0L) {
            throw new GmSSLException("gmssl: Key not initialized.");
        }

        if (dataBytes == null
            || dataBytes.length > MAX_PLAINTEXT_SIZE) {
            throw new GmSSLException("gmssl: Invalid SM9 encrypt parameters.");
        }

        byte[] encryptedBytes = GmSSLJNI.sm9_encrypt(this.masterKey, id, dataBytes);
        if (encryptedBytes == null) {
            throw new GmSSLException("gmssl: SM9 encrypt failure.");
        }

        return encryptedBytes;
    }
}
