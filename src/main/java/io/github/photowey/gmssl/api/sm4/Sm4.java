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
package io.github.photowey.gmssl.api.sm4;

import java.util.Objects;

import io.github.photowey.gmssl.core.constant.GmSSLConstants;
import io.github.photowey.gmssl.core.exception.GmSSLException;
import io.github.photowey.gmssl.core.util.Bytes;
import io.github.photowey.gmssl.jni.GmSSLJNI;

/**
 * {@code Sm4}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/07
 */
public class Sm4 {

    public final static int KEY_SIZE = GmSSLConstants.SM4.SM4_KEY_SIZE;
    public final static int BLOCK_SIZE = GmSSLConstants.SM4.SM4_BLOCK_SIZE;

    private final byte[] key;

    private long sm4Key;

    /**
     * 默认: encrypt: true
     *
     * @param key {@code SM4} key
     */
    public Sm4(byte[] key) {
        this(key, true);
    }

    public Sm4(byte[] key, boolean encryptMode) {
        this(key, encryptMode, true);
    }

    public Sm4(byte[] key, boolean encryptMode, boolean init) {
        if (key == null) {
            throw new GmSSLException("gmssl: SM4 key can't bu null.");
        }
        if (KEY_SIZE != key.length) {
            throw new GmSSLException("gmssl: Invalid SM4 key length.");
        }

        this.key = key;

        if (!init) {
            return;
        }

        this.sm4Key = GmSSLJNI.sm4_key_new();
        if (0L == this.sm4Key) {
            throw new GmSSLException("gmssl: Generate SM4 key failed");
        }

        if (encryptMode) {
            if (GmSSLJNI.sm4_set_encrypt_key(sm4Key, key) != 1) {
                throw new GmSSLException("gmssl: Set SM4 encrypt key failed");
            }

            return;
        }

        if (GmSSLJNI.sm4_set_decrypt_key(sm4Key, key) != 1) {
            throw new GmSSLException("gmssl: Set SM4 decrypt key failed");
        }
    }

    // ----------------------------------------------------------------

    public Sm4 copyToEncryptor() {
        return new Sm4(this.key, true);
    }

    public Sm4 copyToDecryptor() {
        return new Sm4(this.key, false);
    }

    // ----------------------------------------------------------------

    public String encrypt(String data) {
        byte[] cipherBytes = this.encryptBytes(data);
        return Bytes.toHex(cipherBytes);
    }

    public void encrypt(byte[] in, byte[] out) {
        this.encrypt(in, 0, out, 0);
    }

    public void encrypt(byte[] in, int inOffset, byte[] out, int outOffset) {
        if (in == null
            || inOffset < 0
            || inOffset + BLOCK_SIZE <= 0
            || inOffset + BLOCK_SIZE > in.length) {
            throw new GmSSLException("gmssl: Invalid input parameters");
        }
        if (out == null
            || outOffset < 0
            || outOffset + BLOCK_SIZE <= 0
            || outOffset + BLOCK_SIZE > in.length) {
            throw new GmSSLException("gmssl: Invalid output parameters");
        }

        if (GmSSLJNI.sm4_encrypt(sm4Key, in, inOffset, out, outOffset) != 1) {
            throw new GmSSLException("gmssl: SM4 encrypt failed");
        }
    }

    public byte[] encryptBytes(String data) {
        byte[] dataBytes = data.getBytes();
        byte[] cipherBytes = new byte[Sm4.BLOCK_SIZE];

        this.encrypt(dataBytes, cipherBytes);

        return cipherBytes;
    }

    // ----------------------------------------------------------------

    public String decrypt(String encrypted) {
        byte[] decryptedBytes = this.decryptBytes(encrypted);

        return new String(decryptedBytes);
    }

    public void decrypt(byte[] in, byte[] out) {
        this.decrypt(in, 0, out, 0);
    }

    public void decrypt(byte[] in, int inOffset, byte[] out, int outOffset) {
        this.encrypt(in, inOffset, out, outOffset);
    }

    public byte[] decryptBytes(String encrypted) {
        byte[] cipherBytes = Bytes.toBytes(encrypted);
        byte[] decryptedBytes = new byte[Objects.requireNonNull(cipherBytes).length];

        this.decrypt(cipherBytes, decryptedBytes);

        return decryptedBytes;
    }
}
