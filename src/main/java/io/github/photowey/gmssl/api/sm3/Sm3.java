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
 * {@code Sm3}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/09
 */
public class Sm3 implements AutoCloseable {

    public final static int DIGEST_SIZE = GmSSLConstants.SM3.SM3_DIGEST_SIZE;

    private long ctx = 0;

    public Sm3() {
        this.ctx = GmSSLJNI.sm3_ctx_new();
        if (this.ctx == 0) {
            throw new GmSSLException("gmssl: New SM3 ctx failed.");
        }

        if (GmSSLJNI.sm3_init(this.ctx) != 1) {
            throw new GmSSLException("gmssl: Init SM3 ctx failed.");
        }
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
            throw new GmSSLException("gmssl: Invalid input parameters.");
        }
        if (GmSSLJNI.sm3_update(this.ctx, data, offset, len) != 1) {
            throw new GmSSLException("gmssl: SM3 update failed.");
        }
    }

    // ----------------------------------------------------------------

    public byte[] digestBytes(String data) {
        this.update(data.getBytes());

        return this.digest();
    }

    public String digest(String data) {
        byte[] digestBytes = this.digestBytes(data);

        return Bytes.toHex(digestBytes);
    }

    public byte[] digest() {
        byte[] digest = new byte[DIGEST_SIZE];
        if (GmSSLJNI.sm3_finish(this.ctx, digest) != 1) {
            throw new GmSSLException("gmssl: SM3 finish failed.");
        }

        this.reset();

        return digest;
    }

    // ----------------------------------------------------------------

    public void reset() {
        if (GmSSLJNI.sm3_init(this.ctx) != 1) {
            throw new GmSSLException("gmssl: Reset SM3 ctx failed.");
        }
    }

    // ----------------------------------------------------------------

    @Override
    public void close() throws Exception {
        GmSSLJNI.sm3_ctx_free(this.ctx);
    }
}
