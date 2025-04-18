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
package io.github.photowey.gmssl.api.sm4;

import io.github.photowey.gmssl.core.util.Bytes;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@code Sm4Test}
 *
 * @author weichangjun
 * @version 1.0.0
 * @since 2025/04/07
 */
@Slf4j
class Sm4Test {

    byte[] key;
    Sm4 template;

    @BeforeEach
    void init() {
        this.key = new byte[] {
            49, 50, 51, 52,
            53, 54, 55, 56,
            56, 55, 54, 53,
            52, 51, 50, 49
        };

        this.template = new Sm4(key, true, false);
    }

    // ----------------------------------------------------------------

    @Test
    void testEncrypt_v1() {
        String data = "1234567887654321";
        Sm4 encryptor = this.template.copyToEncryptor();
        String cipherHex = encryptor.encrypt(data);
        Assertions.assertNotNull(cipherHex, "data is empty exception!");

        // 4a7dc8fc6f7fb9bac989bbf8a5f194a7
        log.info("v1: the cipherHex is:{}", cipherHex);
    }

    @Test
    void testEncrypt_v2() {
        String data = "1234567887654321";
        byte[] dataBytes = data.getBytes();
        byte[] cipherBytes = new byte[Sm4.BLOCK_SIZE];

        Sm4 encryptor = this.template.copyToEncryptor();
        encryptor.encrypt(dataBytes, 0, cipherBytes, 0);

        String cipherHex = Bytes.toHex(cipherBytes);
        Assertions.assertNotNull(cipherHex, "data is empty exception!");
        // 4a7dc8fc6f7fb9bac989bbf8a5f194a7
        log.info("v2: the cipherHex is:{}", cipherHex);
    }

    @Test
    void testEncrypt_chinese() {
        String data = "窗前明月光1";
        byte[] dataBytes = data.getBytes();
        byte[] cipherBytes = new byte[Sm4.BLOCK_SIZE];

        Sm4 encryptor = this.template.copyToEncryptor();
        encryptor.encrypt(dataBytes, 0, cipherBytes, 0);

        String cipherHex = Bytes.toHex(cipherBytes);

        Assertions.assertNotNull(cipherHex, "data is empty exception!");

        // 1e00c2ccd46f083e43e3c38b8ed40bd6
        log.info("the chinese cipherHex is:{}", cipherHex);
    }

    // ----------------------------------------------------------------

    @Test
    void testDecrypt_v1() {
        String encrypted = "4a7dc8fc6f7fb9bac989bbf8a5f194a7";
        Sm4 decryptor = this.template.copyToDecryptor();
        String decrypted = decryptor.decrypt(encrypted);

        Assertions.assertEquals(
            "1234567887654321",
            decrypted,
            "original value is not equal to the expected value after decryption!"
        );
    }

    @Test
    void testDecrypt_v2() {
        String cipherHex = "4a7dc8fc6f7fb9bac989bbf8a5f194a7";
        byte[] cipherBytes = Bytes.toBytes(cipherHex);
        byte[] decryptedBytes = new byte[cipherBytes.length];

        Sm4 decryptor = this.template.copyToDecryptor();
        decryptor.decrypt(cipherBytes, 0, decryptedBytes, 0);

        String decrypted = new String(decryptedBytes);

        Assertions.assertEquals(
            "1234567887654321",
            decrypted,
            "original value is not equal to the expected value after decryption!"
        );
    }

    @Test
    void testDecrypt_chinese() {
        String cipherHex = "1e00c2ccd46f083e43e3c38b8ed40bd6";
        byte[] cipherBytes = Bytes.toBytes(cipherHex);
        byte[] decryptedBytes = new byte[cipherBytes.length];

        Sm4 decryptor = this.template.copyToDecryptor();
        decryptor.decrypt(cipherBytes, 0, decryptedBytes, 0);

        String decrypted = new String(decryptedBytes);

        Assertions.assertEquals(
            "窗前明月光1",
            decrypted,
            "original value is not equal to the expected value after decryption!"
        );
    }

}
