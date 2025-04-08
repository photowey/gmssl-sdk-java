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
 * {@code Sm4Ctr}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/07
 */
public class Sm4Ctr {

    public final static int KEY_SIZE = GmSSLConstants.SM4.SM4_KEY_SIZE;
    public final static int IV_SIZE = GmSSLConstants.SM4.SM4_BLOCK_SIZE;
    public final static int BLOCK_SIZE = GmSSLConstants.SM4.SM4_BLOCK_SIZE;

    private long ctx = 0;
    private boolean initialized = false;

    private byte[] key;
    private byte[] iv;

    public Sm4Ctr() {
        this.ctx = GmSSLJNI.sm4_ctr_ctx_new();
        if (0L == this.ctx) {
            throw new GmSSLException("gmssl: Init SM4 ctr ctx failed.");
        }

        this.initialized = false;
    }

    public Sm4Ctr(byte[] key, byte[] iv) {
        this.ctx = GmSSLJNI.sm4_ctr_ctx_new();
        if (0L == this.ctx) {
            throw new GmSSLException("gmssl: Init SM4 ctr ctx failed.");
        }

        this.initialized = false;
        this.key = key;
        this.iv = iv;

        this.init(key, iv);
    }

    public void init(byte[] key, byte[] iv) {
        if (key == null
            || key.length != KEY_SIZE
            || iv == null
            || iv.length != IV_SIZE) {
            throw new GmSSLException("gmssl: Invalid SM4 ctr parameters.");
        }

        this.tryInit(key, iv);

        this.initialized = true;
    }

    // ----------------------------------------------------------------

    public String encrypt(byte[] in, int inLen, byte[] out) {
        return this.encrypt(in, 0, inLen, out, 0);
    }

    public String encrypt(byte[] in, int inOffset, int inLen, byte[] out, int outOffset) {
        int cipherLen = this.update(in, inOffset, inLen, out, outOffset);
        cipherLen += this.doFinal(out, cipherLen);

        byte[] encryptedBytes = Arrays.copyOfRange(out, 0, cipherLen);

        return Bytes.toHex(encryptedBytes);
    }

    public String decrypt(byte[] in, int inLen, byte[] out) {
        return this.decrypt(in, 0, inLen, out, 0);
    }

    public String decrypt(byte[] in, int inOffset, int inLen, byte[] out, int outOffset) {
        int plainLen = this.update(in, inOffset, inLen, out, outOffset);
        plainLen += this.doFinal(out, plainLen);

        byte[] decryptedBytes = Arrays.copyOfRange(out, 0, plainLen);

        return new String(decryptedBytes);
    }

    // ----------------------------------------------------------------

    public int update(byte[] in, int inLen, byte[] out) {
        return this.update(in, 0, inLen, out, 0);
    }

    public int update(byte[] in, int inOffset, int inLen, byte[] out, int outOffset) {
        if (!this.initialized) {
            throw new GmSSLException("gmssl: SM4 ctr ctx has not been initialized yet?");
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

        int outLen = GmSSLJNI.sm4_ctr_encrypt_update(this.ctx, in, inOffset, inLen, out, outOffset);
        if (outLen < 0) {
            throw new GmSSLException("gmssl: SM4 ctr encrypt update failed");
        }

        return outLen;
    }

    public int doFinal(byte[] out, int outOffset) {
        if (!this.initialized) {
            throw new GmSSLException("gmssl: SM4 ctr ctx has not been initialized yet?");
        }

        if (out == null
            || outOffset < 0
            || out.length < outOffset) {
            throw new GmSSLException("gmssl: Invalid output parameters");
        }

        int outLen = GmSSLJNI.sm4_ctr_encrypt_finish(this.ctx, out, outOffset);
        if (outLen < 0) {
            throw new GmSSLException("gmssl: SM4 ctr encrypt finish failed");
        }

        this.reset();
        return outLen;
    }

    // ----------------------------------------------------------------

    private void reset() {
        this.initialized = false;
    }

    private void tryInit(byte[] key, byte[] iv) {
        if (GmSSLJNI.sm4_ctr_encrypt_init(this.ctx, key, iv) != 1) {
            throw new GmSSLException("gmssl: SM4 ctr encrypt init failed.");
        }
    }
}
