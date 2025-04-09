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
import io.github.photowey.gmssl.jni.GmSSLJNI;

/**
 * {@code Sm3Pbkdf2}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/09
 */
public class Sm3Pbkdf2 {

    public final static int MAX_SALT_SIZE = GmSSLConstants.SM3.SM3_PBKDF2_MAX_SALT_SIZE;
    public final static int DEFAULT_SALT_SIZE = GmSSLConstants.SM3.SM3_PBKDF2_DEFAULT_SALT_SIZE;
    public final static int MIN_ITER = GmSSLConstants.SM3.SM3_PBKDF2_MIN_ITER;
    public final static int MAX_ITER = GmSSLConstants.SM3.SM3_PBKDF2_MAX_ITER;
    public final static int MAX_KEY_SIZE = GmSSLConstants.SM3.SM3_PBKDF2_MAX_KEY_SIZE;

    public byte[] deriveKey(String password, byte[] salt, int iter, int keyLen) {
        if (password == null) {
            throw new GmSSLException("gmssl: SM3 pbkdf2 password can't be null.");
        }
        if (salt == null) {
            throw new GmSSLException("gmssl: SM3 pbkdf2 salt can't be null.");
        }
        if (salt.length > MAX_SALT_SIZE) {
            throw new GmSSLException("gmssl: Invalid SM3 pbkdf2 salt length.");
        }

        if (iter < MIN_ITER || iter > MAX_ITER) {
            throw new GmSSLException("gmssl: Invalid SM3 pbkdf2 iter.");
        }
        if (keyLen < 0 || keyLen > MAX_KEY_SIZE) {
            throw new GmSSLException("gmssl: Invalid SM3 pbkdf2 key length.");
        }

        byte[] key = GmSSLJNI.sm3_pbkdf2(password, salt, iter, keyLen);
        if (key == null) {
            throw new GmSSLException("gmssl: Derive SM3 pbkdf2 key failure");
        }

        return key;
    }
}
