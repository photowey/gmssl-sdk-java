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
 * {@code Sm3HmacTest}
 *
 * @author weichangjun
 * @version 1.0.0
 * @since 2025/04/09
 */
@Slf4j
class Sm3HmacTest {

    @Test
    void testMac() {
        String data = "gmssl";

        Random rng = new GmSSLRandom();
        byte[] key = rng.randBytes(Sm3Hmac.MAC_SIZE);

        Sm3Hmac sm3hmac = new Sm3Hmac(key);
        sm3hmac.update(data.getBytes(), 0, 3);
        byte[] mac = sm3hmac.generate();

        String macHex = Bytes.toHex(mac);

        Assertions.assertNotNull(macHex, "data is empty exception!");

        // 18d698e93a6a403b3360945de5e831dce0304a4acbe98a7955bcc2d93082305f
        log.info("the mac hex is:{}", macHex);
    }

    @Test
    void testMac_simple() {
        String data = "gmssl";

        Random rng = new GmSSLRandom();
        byte[] key = rng.randBytes(Sm3Hmac.MAC_SIZE);

        Sm3Hmac sm3hmac = new Sm3Hmac(key);
        String macHex = sm3hmac.mac(data);
        Assertions.assertNotNull(macHex, "data is empty exception!");

        // d65f2798e72a882992c8d6330e0d59a5398a576134a27e1d228494a6cd65999e
        log.info("simple: the mac hex is:{}", macHex);
    }

}
