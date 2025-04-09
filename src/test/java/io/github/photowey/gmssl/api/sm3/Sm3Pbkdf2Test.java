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

import io.github.photowey.gmssl.api.random.GmSSLRandom;
import io.github.photowey.gmssl.api.random.Random;
import io.github.photowey.gmssl.core.util.Bytes;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * {@code Sm3Pbkdf2Test}
 *
 * @author weichangjun
 * @version 1.0.0
 * @since 2025/04/09
 */
@Slf4j
class Sm3Pbkdf2Test {

    @Test
    void testKey() {
        Sm3Pbkdf2 kdf = new Sm3Pbkdf2();

        Random rng = new GmSSLRandom();
        byte[] salt = rng.randBytes(Sm3Pbkdf2.DEFAULT_SALT_SIZE);

        String pass = "P@ssw0rd";
        byte[] key = kdf.deriveKey(pass, salt, Sm3Pbkdf2.MIN_ITER * 2, 16);
        String keyHex = Bytes.toHex(key);

        Assertions.assertNotNull(keyHex, "data is empty exception!");

        // 6c2f16158c59c53a4258c4f50be77942
        log.info("the key hex is:{}", keyHex);
    }
}
