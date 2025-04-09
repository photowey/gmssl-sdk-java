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

import io.github.photowey.gmssl.core.exception.GmSSLException;
import io.github.photowey.gmssl.jni.GmSSLJNI;

/**
 * {@code Sm9Signature}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/10
 */
public class Sm9Signature {

    private long ctx = 0;
    private boolean initialized = false;
    private boolean signMode = true;

    public Sm9Signature(boolean signMode) {
        this.ctx = GmSSLJNI.sm9_sign_ctx_new();
        if (this.ctx == 0L) {
            throw new GmSSLException("gmssl: New sign ctx failure.");
        }

        if (signMode) {
            if (GmSSLJNI.sm9_sign_init(this.ctx) != 1) {
                throw new GmSSLException("gmssl: SM9 sign init failure.");
            }
        } else {
            if (GmSSLJNI.sm9_verify_init(this.ctx) != 1) {
                throw new GmSSLException("gmssl: SM9 verify init failure.");
            }
        }
        this.initialized = true;
        this.signMode = signMode;
    }

    public void reset(boolean signMode) {
        if (signMode) {
            if (GmSSLJNI.sm9_sign_init(this.ctx) != 1) {
                throw new GmSSLException("gmssl: SM9 sign init failure.");
            }
        } else {
            if (GmSSLJNI.sm9_verify_init(this.ctx) != 1) {
                throw new GmSSLException("gmssl: SM9 verify init failure.");
            }
        }
        this.initialized = true;
        this.signMode = signMode;
    }

    public void update(byte[] data, int offset, int len) {
        if (!this.initialized) {
            throw new GmSSLException("gmssl: SM9 sign ctx not Initialized.");
        }

        if (data == null
            || offset < 0
            || len < 0
            || offset + len <= 0
            || data.length < offset + len) {
            throw new GmSSLException("gmssl: Invalid SM9 update parameters.");
        }
        if (this.signMode) {
            if (GmSSLJNI.sm9_sign_update(this.ctx, data, offset, len) != 1) {
                throw new GmSSLException("gmssl: SM9 sign update failure.");
            }
        } else {
            if (GmSSLJNI.sm9_verify_update(this.ctx, data, offset, len) != 1) {
                throw new GmSSLException("gmssl: SM9 verify update failure.");
            }
        }
    }

    public void update(byte[] data) {
        update(data, 0, data.length);
    }

    public byte[] sign(Sm9SignKey signKey) {
        if (!this.initialized) {
            throw new GmSSLException("gmssl: SM9 sign ctx not Initialized.");
        }
        if (!this.signMode) {
            throw new GmSSLException("gmssl: Not sign mode.");
        }

        byte[] signature = GmSSLJNI.sm9_sign_finish(this.ctx, signKey.getKey());
        if (signature == null) {
            throw new GmSSLException("gmssl: SM9 sign finish failure.");
        }

        this.initialized = false;
        return signature;
    }

    public boolean verify(byte[] signature, Sm9SignMasterKey masterPublicKey, String id) {
        if (!this.initialized) {
            throw new GmSSLException("gmssl: SM9 sign ctx not Initialized.");
        }
        if (this.signMode) {
            throw new GmSSLException("gmssl: Not sign mode.");
        }

        int ret =
            GmSSLJNI.sm9_verify_finish(ctx, signature, masterPublicKey.getPublicMasterKey(), id);
        this.initialized = false;

        return ret == 1;
    }
}
