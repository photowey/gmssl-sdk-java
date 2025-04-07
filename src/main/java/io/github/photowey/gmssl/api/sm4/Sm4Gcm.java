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

import io.github.photowey.gmssl.core.constant.GmSSLConstants;
import io.github.photowey.gmssl.core.exception.GmSSLException;
import io.github.photowey.gmssl.jni.GmSSLJNI;

/**
 * {@code Sm4Gcm}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/07
 */
public class Sm4Gcm {

    public final static int KEY_SIZE = GmSSLConstants.SM4.SM4_KEY_SIZE;
    public final static int MIN_IV_SIZE = GmSSLConstants.SM4.SM4_GCM_MIN_IV_SIZE;
    public final static int MAX_IV_SIZE = GmSSLConstants.SM4.SM4_GCM_MAX_IV_SIZE;
    public final static int DEFAULT_IV_SIZE = GmSSLConstants.SM4.SM4_GCM_DEFAULT_IV_SIZE;
    public final static int MIN_TAG_SIZE = 8;
    public final static int MAX_TAG_SIZE = GmSSLConstants.SM4.SM4_GCM_MAX_TAG_SIZE;
    public final static int BLOCK_SIZE = GmSSLConstants.SM4.SM4_BLOCK_SIZE;

    private long ctx = 0;
    private boolean encrypt = true;
    private boolean initialized = false;

    public Sm4Gcm() {
        this.ctx = GmSSLJNI.sm4_gcm_ctx_new();
        if (this.ctx == 0) {
            throw new GmSSLException("gmssl: Init SM4 gcm ctx failed.");
        }
        this.initialized = false;
    }

    public void init(byte[] key, byte[] iv, byte[] aad, int tagLen, boolean encrypt) {
        if (key == null
            || key.length != KEY_SIZE
            || iv == null
            || iv.length < MIN_IV_SIZE
            || iv.length > MAX_IV_SIZE
            || tagLen < MIN_TAG_SIZE
            || tagLen > MAX_TAG_SIZE) {
            throw new GmSSLException("gmssl: Invalid SM4 gcm parameters.");
        }

        this.tryInit(key, iv, aad, tagLen, encrypt);

        this.encrypt = encrypt;
        this.initialized = true;
    }

    private void tryInit(byte[] key, byte[] iv, byte[] aad, int tagLen, boolean encrypt) {
        if (encrypt) {
            if (GmSSLJNI.sm4_gcm_encrypt_init(this.ctx, key, iv, aad, tagLen) != 1) {
                throw new GmSSLException("gmssl: SM4 gcm encrypt init failed.");
            }

            return;
        }

        if (GmSSLJNI.sm4_gcm_decrypt_init(this.ctx, key, iv, aad, tagLen) != 1) {
            throw new GmSSLException("gmssl: SM4 gcm decrypt init failed.");
        }
    }

    public int update(byte[] in, int inOffset, int inLen, byte[] out, int outOffset) {
        if (!this.initialized) {
            throw new GmSSLException("gmssl: SM4 gcm ctx has not been initialized yet?");
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
        if (this.encrypt) {
            int outLen =
                GmSSLJNI.sm4_gcm_encrypt_update(this.ctx, in, inOffset, inLen, out, outOffset);
            if (outLen < 0) {
                throw new GmSSLException("gmssl: SM4 gcm encrypt update failed");
            }

            return outLen;
        }

        int outLen = GmSSLJNI.sm4_gcm_decrypt_update(this.ctx, in, inOffset, inLen, out, outOffset);
        if (outLen < 0) {
            throw new GmSSLException("gmssl: SM4 gcm decrypt update failed");
        }

        return outLen;
    }

    public int doFinal(byte[] out, int outOffset) {
        if (!this.initialized) {
            throw new GmSSLException("gmssl: SM4 gcm ctx has not been initialized yet?");
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
        if (this.encrypt) {
            int outLen = GmSSLJNI.sm4_gcm_encrypt_finish(this.ctx, out, outOffset);
            if (outLen < 0) {
                throw new GmSSLException("gmssl: SM4 gcm encrypt finish failed");
            }

            return outLen;
        }

        int outLen = GmSSLJNI.sm4_gcm_decrypt_finish(this.ctx, out, outOffset);
        if (outLen < 0) {
            throw new GmSSLException("gmssl: SM4 gcm decrypt finish failed");
        }

        return outLen;
    }

    private void reset() {
        this.initialized = false;
    }
}
