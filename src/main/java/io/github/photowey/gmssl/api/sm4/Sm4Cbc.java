package io.github.photowey.gmssl.api.sm4;

import io.github.photowey.gmssl.core.constant.GmSSLConstants;
import io.github.photowey.gmssl.core.exception.GmSSLException;
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
    private boolean encrypt = true;
    private boolean initialized = false;

    public Sm4Cbc() {
        this.ctx = GmSSLJNI.sm4_cbc_ctx_new();
        if (this.ctx == 0) {
            throw new GmSSLException("gmssl: Init SM4 cbc ctx failed.");
        }

        this.initialized = false;
    }

    public void init(byte[] key, byte[] iv) {
        this.init(key, iv, true);
    }

    public void init(byte[] key, byte[] iv, boolean encrypt) {
        if (key == null
            || key.length != KEY_SIZE
            || iv == null
            || iv.length != IV_SIZE) {
            throw new GmSSLException("gmssl: Invalid SM4 cbc parameters.");
        }

        this.tryInit(key, iv, encrypt);

        this.encrypt = encrypt;
        this.initialized = true;
    }

    private void tryInit(byte[] key, byte[] iv, boolean encrypt) {
        if (encrypt) {
            if (GmSSLJNI.sm4_cbc_encrypt_init(this.ctx, key, iv) != 1) {
                throw new GmSSLException("gmssl: SM4 cbc encrypt init failed.");
            }

            return;
        }

        if (GmSSLJNI.sm4_cbc_decrypt_init(this.ctx, key, iv) != 1) {
            throw new GmSSLException("gmssl: SM4 cbc decrypt init failed.");
        }
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
        if (this.encrypt) {
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
        if (this.encrypt) {
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
}
