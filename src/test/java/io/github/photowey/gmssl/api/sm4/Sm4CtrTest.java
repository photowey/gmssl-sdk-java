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
package io.github.photowey.gmssl.api.sm4;

import java.util.Arrays;

import io.github.photowey.gmssl.core.util.Bytes;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@code Sm4CtrTest}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/08
 */
@Slf4j
class Sm4CtrTest {

    private Sm4Ctr sm4Ctr;

    private byte[] key;
    private byte[] iv;

    @BeforeEach
    void init() {
        this.sm4Ctr = new Sm4Ctr();
        this.key = new byte[] {
            99, -49, -44, -61,
            104, 76, -65, 88,
            55, 54, 48, -81,
            99, -10, 50, 22
        };
        this.iv = new byte[] {
            -127, 39, -104, -97,
            61, -119, 85, -18,
            -14, -79, 47, -92,
            -113, 92, 28, -34
        };
    }

    @Test
    void testEncrypt_v1() {
        String data1 = "gmssl";
        String data2 = "_";
        String data3 = "v3";

        byte[] ciphertext = new byte[64];

        sm4Ctr.init(key, iv);

        int cipherLen = sm4Ctr.update(
            data1.getBytes(), 0, data1.length(), ciphertext, 0);
        cipherLen += sm4Ctr.update(
            data2.getBytes(), 0, data2.length(), ciphertext, cipherLen);
        cipherLen += sm4Ctr.update(
            data3.getBytes(), 0, data3.length(), ciphertext, cipherLen);

        cipherLen += sm4Ctr.doFinal(ciphertext, cipherLen);

        byte[] encryptedBytes = Arrays.copyOfRange(ciphertext, 0, cipherLen);
        String encrypted = Bytes.toHex(encryptedBytes);

        Assertions.assertNotNull(encrypted, "data is empty exception!");
        // 912c3317275d8e5f
        log.info("the encrypt cipher hex is:{}", encrypted);
    }

    @Test
    void testEncrypt_threshold() {
        String data = "123456781234567812345678123456781234567812345678";

        byte[] ciphertext = new byte[64];
        sm4Ctr.init(key, iv);

        int cipherLen = sm4Ctr.update(
            data.getBytes(), 0, data.length(), ciphertext, 0);

        cipherLen += sm4Ctr.doFinal(ciphertext, cipherLen);

        byte[] encryptedBytes = Arrays.copyOfRange(ciphertext, 0, cipherLen);
        String encrypted = Bytes.toHex(encryptedBytes);

        Assertions.assertNotNull(encrypted, "data is empty exception!");
        // c77373507e34cf544e367e4ec75a36f8beaa9a070d90b71242543871a1b0bafb1d6e2823466b72b60e9b0b5a3c0e9edf
        log.info("threshold: the encrypt cipher hex is:{}", encrypted);
    }

    @Test
    void testEncrypt_simple() {
        String data = "123456781234567812345678123456781234567812345678";

        byte[] ciphertext = new byte[64];
        sm4Ctr.init(key, iv);

        String encrypted = sm4Ctr.encrypt(
            data.getBytes(), 0, data.length(), ciphertext, 0);

        Assertions.assertNotNull(encrypted, "data is empty exception!");
        // c77373507e34cf544e367e4ec75a36f8beaa9a070d90b71242543871a1b0bafb1d6e2823466b72b60e9b0b5a3c0e9edf
        log.info("threshold: the encrypt cipher hex is:{}", encrypted);
    }

    @Test
    void testEncrypt_chinese() {
        String data = "干燥的物质世界，湿润的精神原野。";

        byte[] ciphertext = new byte[64];
        sm4Ctr.init(key, iv);

        String encrypted = sm4Ctr.encrypt(
            data.getBytes(), 0, data.length() * 3, ciphertext, 0);

        Assertions.assertNotNull(encrypted, "data is empty exception!");

        // 13f8f283cca71ff6fbe3c4d31ad8a924370e4ea6b4493ca695dfb4a322206a59a8bba9a994f8db6bb136d1e987db2965
        log.info("chinese: the encrypt cipher hex is:{}", encrypted);
    }

    @Test
    void testDecrypt() {
        String data = "gmssl_v3";
        String encrypted = "912c3317275d8e5f";

        byte[] encryptedBytes = Bytes.toBytes(encrypted);

        byte[] cipherBytes = new byte[64];

        sm4Ctr.init(key, iv);

        int plainLen = sm4Ctr.update(
            encryptedBytes, 0, encrypted.length() / 2, cipherBytes, 0);
        plainLen += sm4Ctr.doFinal(cipherBytes, plainLen);

        byte[] decryptedBytes = Arrays.copyOfRange(cipherBytes, 0, plainLen);
        String decrypted = new String(decryptedBytes);

        Assertions.assertEquals(data, decrypted, "data is empty exception!");
    }

    @Test
    void testDecrypt_chinese() {
        String data = "干燥的物质世界，湿润的精神原野。";
        String encrypted =
            "13f8f283cca71ff6fbe3c4d31ad8a924370e4ea6b4493ca"
                + "695dfb4a322206a59a8bba9a994f8db6bb136d1e987db2965";

        byte[] encryptedBytes = Bytes.toBytes(encrypted);

        byte[] cipherBytes = new byte[64];

        sm4Ctr.init(key, iv);

        int plainLen = sm4Ctr.update(
            encryptedBytes, 0, encrypted.length() / 2, cipherBytes, 0);
        plainLen += sm4Ctr.doFinal(cipherBytes, plainLen);

        byte[] decryptedBytes = Arrays.copyOfRange(cipherBytes, 0, plainLen);
        String decrypted = new String(decryptedBytes);

        Assertions.assertEquals(data, decrypted, "data is empty exception!");
    }

    @Test
    void testDecrypt_threshold() {
        String data = "123456781234567812345678123456781234567812345678";
        String encrypted =
            "c77373507e34cf544e367e4ec75a36f8beaa9a070d90b712425"
                + "43871a1b0bafb1d6e2823466b72b60e9b0b5a3c0e9edf";

        byte[] encryptedBytes = Bytes.toBytes(encrypted);

        byte[] cipherBytes = new byte[64];

        sm4Ctr.init(key, iv);

        int plainLen = sm4Ctr.update(
            encryptedBytes, 0, encrypted.length() / 2, cipherBytes, 0);
        plainLen += sm4Ctr.doFinal(cipherBytes, plainLen);

        byte[] decryptedBytes = Arrays.copyOfRange(cipherBytes, 0, plainLen);
        String decrypted = new String(decryptedBytes);

        Assertions.assertEquals(data, decrypted, "data is empty exception!");
    }

    @Test
    void testDecrypt_simple() {
        String data = "123456781234567812345678123456781234567812345678";
        String encrypted =
            "c77373507e34cf544e367e4ec75a36f8beaa9a070d90b712425"
                + "43871a1b0bafb1d6e2823466b72b60e9b0b5a3c0e9edf";

        byte[] encryptedBytes = Bytes.toBytes(encrypted);
        byte[] cipherBytes = new byte[64];

        sm4Ctr.init(key, iv);

        String decrypted = sm4Ctr.decrypt(
            encryptedBytes, 0, encrypted.length() / 2, cipherBytes, 0);

        Assertions.assertEquals(data, decrypted, "data is empty exception!");
    }
}
