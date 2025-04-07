package io.github.photowey.gmssl.api.sm4;

import io.github.photowey.gmssl.core.constant.GmSSLConstants;
import io.github.photowey.gmssl.core.exception.GmSSLException;
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

    public Sm4Ctr() {
        this.ctx = GmSSLJNI.sm4_ctr_ctx_new();
        if (this.ctx == 0) {
            throw new GmSSLException("gmssl: Init SM4 ctr ctx failed.");
        }

        this.initialized = false;
    }

    public void init(byte[] key, byte[] iv) {
        if (key == null
            || key.length != KEY_SIZE
            || iv == null
            || iv.length != IV_SIZE) {
            throw new GmSSLException("gmssl: Invalid SM4 ctr parameters.");
        }

        if (GmSSLJNI.sm4_ctr_encrypt_init(this.ctx, key, iv) != 1) {
            throw new GmSSLException("gmssl: SM4 ctr encrypt init failed.");
        }

        this.initialized = true;
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

    private void reset() {
        this.initialized = false;
    }
}
