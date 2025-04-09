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
package io.github.photowey.gmssl.api.sm3;

import io.github.photowey.gmssl.core.constant.GmSSLConstants;
import io.github.photowey.gmssl.core.exception.GmSSLException;
import io.github.photowey.gmssl.core.util.Bytes;
import io.github.photowey.gmssl.jni.GmSSLJNI;

/**
 * {@code Sm3Hmac}.
 * {@code SM3} HMAC
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/09
 */
public class Sm3Hmac {

    public final static int MAC_SIZE = GmSSLConstants.SM3.SM3_HMAC_SIZE;

    private byte[] key;
    private long ctx = 0;

    public Sm3Hmac(byte[] key) {
        if (key == null) {
            throw new GmSSLException("gmssl: SM3 hmac key can't be null.");
        }
        this.ctx = GmSSLJNI.sm3_hmac_ctx_new();
        if (0L == this.ctx) {
            throw new GmSSLException("gmssl: New SM3 hmac ctx failed.");
        }
        if (GmSSLJNI.sm3_hmac_init(this.ctx, key) != 1) {
            throw new GmSSLException("gmssl: SM3 hmac init failed.");
        }

        this.key = key;
    }

    // ----------------------------------------------------------------

    public void update(byte[] data) {
        this.update(data, 0, data.length);
    }

    public void update(byte[] data, int offset, int len) {
        if (data == null
            || offset < 0
            || len < 0
            || offset + len <= 0
            || data.length < offset + len) {
            throw new GmSSLException("gmssl: Invalid SM3 hmac update parameters.");
        }
        if (GmSSLJNI.sm3_hmac_update(this.ctx, data, offset, len) != 1) {
            throw new GmSSLException("gmssl: SM3 hmac update failed.");
        }
    }

    // ----------------------------------------------------------------

    public String mac(String data) {
        byte[] mac = this.macBytes(data);

        return Bytes.toHex(mac);
    }

    public byte[] macBytes(String data) {
        this.update(data.getBytes(), 0, 3);
        return this.generate();
    }

    // ----------------------------------------------------------------

    public byte[] generate() {
        byte[] mac = new byte[MAC_SIZE];
        if (GmSSLJNI.sm3_hmac_finish(this.ctx, mac) != 1) {
            throw new GmSSLException("gmssl: SM3 hmac finish failed.");
        }
        if (GmSSLJNI.sm3_hmac_init(this.ctx, this.key) != 1) {
            throw new GmSSLException("gmssl: SM3 hmac init failed.");
        }

        return mac;
    }

    // ----------------------------------------------------------------

    public void reset(byte[] key) {
        if (key == null) {
            throw new GmSSLException("gmssl: SM3 hmac key can't be null.");
        }
        if (GmSSLJNI.sm3_hmac_init(this.ctx, key) != 1) {
            throw new GmSSLException("gmssl: SM3 hmac init failed.");
        }

        this.key = key;
    }

}

