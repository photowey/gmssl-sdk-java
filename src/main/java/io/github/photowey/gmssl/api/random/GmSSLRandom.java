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
package io.github.photowey.gmssl.api.random;

import io.github.photowey.gmssl.core.exception.GmSSLException;
import io.github.photowey.gmssl.jni.GmSSLJNI;

/**
 * {@code GmSSLRandom}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/06
 */
public class GmSSLRandom implements Random {

    @Override
    public void randBytes(byte[] out, int offset, int len) {
        if (out == null
            || offset < 0
            || len < 0
            || offset + len <= 0
            || out.length < offset + len) {
            throw new GmSSLException("gmssl: Invalid rand parameters.");
        }

        if (GmSSLJNI.rand_bytes(out, offset, len) != 1) {
            throw new GmSSLException();
        }
    }
}
