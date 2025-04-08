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

import io.github.photowey.gmssl.core.util.Bytes;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * {@code Sm3Test}
 *
 * @author weichangjun
 * @version 1.0.0
 * @since 2025/04/09
 */
@Slf4j
class Sm3Test {

    @Test
    public void testDigest() throws Exception {
        String data = "gmssl";

        try (Sm3 sm3 = new Sm3()) {
            sm3.update(data.getBytes());

            byte[] digestBytes = sm3.digest();

            String digest = Bytes.toHex(digestBytes);

            Assertions.assertNotNull(digest, "data is empty exception!");
            // 0e13ae1cbf793a16078b4b702287de9e6dd530acb159937b9c68ed8e93f5cc3e
            log.info("the sm3 digest hex is:{}", digest);
        }
    }

    @Test
    public void testDigest_simple() throws Exception {
        String data = "gmssl";

        try (Sm3 sm3 = new Sm3()) {
            String digest = sm3.digest(data);

            Assertions.assertNotNull(digest, "data is empty exception!");
            // 0e13ae1cbf793a16078b4b702287de9e6dd530acb159937b9c68ed8e93f5cc3e
            log.info("simple: the sm3 digest hex is:{}", digest);
        }
    }

    @Test
    public void testDigest_chinese_simple() throws Exception {
        String data = "干燥的物质世界，湿润的精神原野！";

        try (Sm3 sm3 = new Sm3()) {
            String digest = sm3.digest(data);

            Assertions.assertNotNull(digest, "data is empty exception!");
            // a006c4a974d9cd5f9f446920fe4de575dc70e5aac4708bea2b6913ac5544a94d
            log.info("chinese.simple: the sm3 digest hex is:{}", digest);
        }
    }

    @Test
    public void testDigest_chinese_simple_long_text() throws Exception {
        String data = "干燥的物质世界，湿润的精神原野！"
            + "干燥的物质世界，湿润的精神原野！"
            + "干燥的物质世界，湿润的精神原野！"
            + "干燥的物质世界，湿润的精神原野！"
            + "干燥的物质世界，湿润的精神原野！"
            + "干燥的物质世界，湿润的精神原野！"
            + "干燥的物质世界，湿润的精神原野！"
            + "干燥的物质世界，湿润的精神原野！"
            + "干燥的物质世界，湿润的精神原野！"
            + "干燥的物质世界，湿润的精神原野！"
            + "干燥的物质世界，湿润的精神原野！";

        try (Sm3 sm3 = new Sm3()) {
            String digest = sm3.digest(data);

            Assertions.assertNotNull(digest, "data is empty exception!");
            // 3b2f160cb93b5324ef5fce90da0017cab0711161ea1d8f5ae0eeebdee2cf831e
            log.info("chinese.simple.long.text: the sm3 digest hex is:{}", digest);
        }
    }
}
