/*
 * Copyright © 2025 the original author or authors.
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

import java.util.Arrays;

import io.github.photowey.gmssl.core.constant.GmSSLConstants;
import io.github.photowey.gmssl.core.exception.GmSSLException;
import io.github.photowey.gmssl.core.util.Bytes;
import io.github.photowey.gmssl.jni.GmSSLJNI;

/**
 * {@code Sm4Cbc}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/07
 */
public class Sm4Cbc {

    public final static int KEY_SIZE = GmSSLConstants.SM4.SM4_KEY_SIZE;
    public final static int IV_SIZE = GmSSLConstants.SM4.SM4_BLOCK_SIZE;
    public final static int BLOCK_SIZE = GmSSLConstants.SM4.SM4_BLOCK_SIZE;

    private long ctx = 0;
    private boolean encryptMode = true;
    private boolean initialized = false;

    private byte[] key;
    private byte[] iv;

    public Sm4Cbc() {
        this.ctx = GmSSLJNI.sm4_cbc_ctx_new();
        if (this.ctx == 0) {
            throw new GmSSLException("gmssl: Init SM4 cbc ctx failed.");
        }

        this.initialized = false;
    }

    public Sm4Cbc(byte[] key, byte[] iv) {
        this(key, iv, true);
    }

    public Sm4Cbc(byte[] key, byte[] iv, boolean encryptMode) {
        this(key, iv, encryptMode, true);
    }

    public Sm4Cbc(byte[] key, byte[] iv, boolean encryptMode, boolean init) {
        this.ctx = GmSSLJNI.sm4_cbc_ctx_new();
        if (this.ctx == 0) {
            throw new GmSSLException("gmssl: Init SM4 cbc ctx failed.");
        }

        this.initialized = false;
        this.key = key;
        this.iv = iv;
        this.encryptMode = encryptMode;

        this.init(key, iv, encryptMode, init);
    }

    // ----------------------------------------------------------------

    public Sm4Cbc copyToEncryptor() {
        return new Sm4Cbc(this.key, this.iv, true);
    }

    public Sm4Cbc copyToDecryptor() {
        return new Sm4Cbc(this.key, this.iv, false);
    }

    // ----------------------------------------------------------------

    public void init(byte[] key, byte[] iv) {
        this.init(key, iv, true);
    }

    public void init(byte[] key, byte[] iv, boolean encryptMode) {
        this.init(key, iv, encryptMode, true);
    }

    public void init(byte[] key, byte[] iv, boolean encryptMode, boolean init) {
        if (key == null
            || key.length != KEY_SIZE
            || iv == null
            || iv.length != IV_SIZE) {
            throw new GmSSLException("gmssl: Invalid SM4 cbc parameters.");
        }

        this.encryptMode = encryptMode;

        if (init) {
            this.tryInit(key, iv, encryptMode);
            this.initialized = true;
        }
    }


    // ----------------------------------------------------------------

    public String encrypt(String data) {
        byte[] dataBytes = data.getBytes();
        return this.encrypt(dataBytes);
    }

    public String encrypt(byte[] dataBytes) {
        byte[] cipherFinalBytes = this.encryptBytes(dataBytes);

        return Bytes.toHex(cipherFinalBytes);
    }

    public byte[] encryptBytes(byte[] dataBytes) {
        byte[] cipherBytes = new byte[dataBytes.length + Sm4Cbc.BLOCK_SIZE];

        this.tryInitIfNecessary();

        int cipherLen = this.update(dataBytes, dataBytes.length, cipherBytes);
        cipherLen += this.doFinal(cipherBytes, cipherLen);

        return Arrays.copyOfRange(cipherBytes, 0, cipherLen);
    }

    // ----------------------------------------------------------------

    public String decrypt(String encrypted) {
        byte[] cipherBytes = Bytes.toBytes(encrypted);
        return this.decrypt(cipherBytes);
    }

    public String decrypt(byte[] cipherBytes) {
        byte[] decryptedBytes = this.decryptBytes(cipherBytes);

        return new String(decryptedBytes);
    }

    public byte[] decryptBytes(byte[] cipherBytes) {
        this.tryInitIfNecessary(false);

        byte[] decrypted = new byte[cipherBytes.length + Sm4Cbc.BLOCK_SIZE];
        int decryptedOffset = 0;
        int cipherOffset = 0;
        int decryptedLen = this.update(
            cipherBytes, cipherOffset, cipherBytes.length, decrypted, decryptedOffset);
        decryptedOffset += decryptedLen;
        decryptedLen += this.doFinal(decrypted, decryptedOffset);

        return Arrays.copyOfRange(decrypted, 0, decryptedLen);
    }

    // ----------------------------------------------------------------

    public int update(byte[] in, int inLen, byte[] out) {
        return this.update(in, 0, inLen, out, 0);
    }

    public int update(byte[] in, int inOffset, int inLen, byte[] out, int outOffset) {
        if (!this.initialized) {
            throw new GmSSLException("gmssl: SM4 cbc ctx has not been initialized yet?");
        }

        if (in == null
            || inOffset < 0
            || inLen < 0
            || inOffset + inLen <= 0
            || in.length < inOffset + inLen) {
            throw new GmSSLException("gmssl: Invalid input parameters");
        }
        if (out == null
            || outOffset < 0
            || out.length < outOffset) {
            throw new GmSSLException("gmssl: Invalid output parameters");
        }

        return this.doUpdate(in, inOffset, inLen, out, outOffset);
    }

    private int doUpdate(byte[] in, int inOffset, int inLen, byte[] out, int outOffset) {
        if (this.encryptMode) {
            int outLen =
                GmSSLJNI.sm4_cbc_encrypt_update(this.ctx, in, inOffset, inLen, out, outOffset);
            if (outLen < 0) {
                throw new GmSSLException("gmssl: SM4 cbc encrypt update failed");
            }

            return outLen;
        }

        int outLen = GmSSLJNI.sm4_cbc_decrypt_update(this.ctx, in, inOffset, inLen, out, outOffset);
        if (outLen < 0) {
            throw new GmSSLException("gmssl: SM4 cbc decrypt update failed");
        }

        return outLen;
    }

    public int doFinal(byte[] out, int outOffset) {
        if (!this.initialized) {
            throw new GmSSLException("gmssl: SM4 cbc ctx has not been initialized yet?");
        }

        if (out == null
            || outOffset < 0
            || out.length < outOffset) {
            throw new GmSSLException("gmssl: Invalid output parameters");
        }

        int outLen = this.doFinish(out, outOffset);

        this.reset();
        return outLen;
    }

    private int doFinish(byte[] out, int outOffset) {
        if (this.encryptMode) {
            int outLen = GmSSLJNI.sm4_cbc_encrypt_finish(this.ctx, out, outOffset);
            if (outLen < 0) {
                throw new GmSSLException("gmssl: SM4 cbc encrypt finish failed");
            }

            return outLen;
        }

        int outLen = GmSSLJNI.sm4_cbc_decrypt_finish(this.ctx, out, outOffset);
        if (outLen < 0) {
            throw new GmSSLException("gmssl: SM4 cbc decrypt finish failed");
        }

        return outLen;
    }

    private void reset() {
        this.initialized = false;
    }

    // ----------------------------------------------------------------

    private void tryInitIfNecessary() {
        this.tryInitIfNecessary(true);
    }

    private void tryInitIfNecessary(boolean encryptMode) {
        if (!this.initialized) {
            this.init(this.key, this.iv, encryptMode);
        }
    }

    private void tryInit(byte[] key, byte[] iv, boolean encryptMode) {
        if (encryptMode) {
            if (GmSSLJNI.sm4_cbc_encrypt_init(this.ctx, key, iv) != 1) {
                throw new GmSSLException("gmssl: SM4 cbc encrypt init failed.");
            }

            return;
        }

        if (GmSSLJNI.sm4_cbc_decrypt_init(this.ctx, key, iv) != 1) {
            throw new GmSSLException("gmssl: SM4 cbc decrypt init failed.");
        }
    }

}
