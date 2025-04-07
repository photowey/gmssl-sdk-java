package io.github.photowey.gmssl.api.sm4;

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

    public Sm4(byte[] key, boolean encrypt) {
        this(key, encrypt, true);
    }

    public Sm4(byte[] key, boolean encrypt, boolean init) {
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

        if (encrypt) {
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

    public String encrypt(String data) {
        byte[] dataBytes = data.getBytes();
        byte[] cipherBytes = new byte[Sm4.BLOCK_SIZE];

        this.encrypt(dataBytes, cipherBytes);

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

    // ----------------------------------------------------------------

    public String decrypt(String encrypted) {
        byte[] cipherBytes = Bytes.toBytes(encrypted);
        byte[] decryptedBytes = new byte[cipherBytes.length];

        this.decrypt(cipherBytes, decryptedBytes);

        return new String(decryptedBytes);
    }

    public void decrypt(byte[] in, byte[] out) {
        this.decrypt(in, 0, out, 0);
    }

    public void decrypt(byte[] in, int inOffset, byte[] out, int outOffset) {
        this.encrypt(in, inOffset, out, outOffset);
    }

    // ----------------------------------------------------------------

    public Sm4 toEncrypt() {
        return new Sm4(this.key, true);
    }

    public Sm4 toDecrypt() {
        return new Sm4(this.key, false);
    }
}
