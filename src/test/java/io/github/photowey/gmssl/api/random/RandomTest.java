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
package io.github.photowey.gmssl.api.random;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * {@code RandomTest}
 *
 * @author weichangjun
 * @version 1.0.0
 * @since 2025/04/06
 */
@Slf4j
class RandomTest {

    @Test
    void testRand() {
        Random random = new GmSSLRandom();
        String rand = random.rand(21);

        Assertions.assertNotNull(rand);
        Assertions.assertEquals(42, rand.length());

        // 3f866acfbc9ea105db5ed1beb755bf56eb2436ced6
        log.info("the rand hex value is: {}", rand);
    }

    @Test
    void testBytes() {
        Random random = new GmSSLRandom();
        byte[] bytes = random.randBytes(21);

        Assertions.assertEquals(21, bytes.length);
    }

}
