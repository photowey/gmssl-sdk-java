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

import java.util.Arrays;
import java.util.Objects;

import io.github.photowey.gmssl.core.util.Bytes;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@code Sm4GcmTest}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/08
 */
@Slf4j
class Sm4GcmTest {

    Sm4Gcm template;

    byte[] key;
    byte[] iv;
    byte[] aad;

    int tagLen;

    @BeforeEach
    public void beforeTest() {
        this.key = new byte[] {
            52, -63, -74, 123,
            75, -42, -109, -94,
            -108, -35, 117, -70,
            95, 126, -71, 6
        };

        this.iv = new byte[] {
            -97, -42, 38, -65,
            37, -75, -26, -119,
            -19, 124, -116, -27
        };

        this.tagLen = Sm4Gcm.MAX_TAG_SIZE;
        this.aad = "Hello: ".getBytes();
        this.template = new Sm4Gcm(this.key, this.iv, this.aad, this.tagLen, true, false);
    }

    @Test
    void testEncrypt() {
        String data = "gmssl";
        byte[] dataBytes = data.getBytes();

        int blockLength = (int) Math.ceil((dataBytes.length + tagLen) / (double) Sm4.BLOCK_SIZE);
        byte[] tempBytes = new byte[blockLength * Sm4.BLOCK_SIZE];

        Sm4Gcm encryptor = this.template.copyToEncryptor();
        int cipherLen = encryptor.update(dataBytes, 0, dataBytes.length, tempBytes, 0);
        cipherLen += encryptor.doFinal(tempBytes, cipherLen);

        byte[] cipherBytes = Arrays.copyOfRange(tempBytes, 0, cipherLen);

        String cipherHex = Bytes.toHex(cipherBytes);
        Assertions.assertNotNull(cipherHex, "data is empty exception!");

        // b4a20037dc223f3e3474304dbb464a86423fa6c6db
        log.info("the encrypt hex is:{}", cipherHex);
    }

    @Test
    void testEncrypt_simple() {
        String data = "gmssl";

        Sm4Gcm encryptor = this.template.copyToEncryptor();
        String cipherHex = encryptor.encrypt(data);
        Assertions.assertNotNull(cipherHex, "data is empty exception!");

        // b4a20037dc223f3e3474304dbb464a86423fa6c6db
        log.info("simple: the encrypt hex is:{}", cipherHex);
    }

    @Test
    public void testDecrypt() {
        String data = "gmssl";
        String encrypted = "b4a20037dc223f3e3474304dbb464a86423fa6c6db";

        byte[] encryptedBytes = Bytes.toBytes(encrypted);
        byte[] tempBytes = new byte[Objects.requireNonNull(encryptedBytes).length + tagLen];

        Sm4Gcm decryptor = this.template.copyToDecryptor();

        int plainLen =
            decryptor.update(encryptedBytes, 0, encryptedBytes.length, tempBytes, 0);
        plainLen += decryptor.doFinal(tempBytes, plainLen);
        byte[] plaintextByte = Arrays.copyOfRange(tempBytes, 0, plainLen);

        String decrypted = new String(plaintextByte);

        Assertions.assertEquals(
            data,
            decrypted,
            "original value is not equal to the expected value after decryption!"
        );
    }

    @Test
    public void testDecrypt_simple() {
        String data = "gmssl";
        String encrypted = "b4a20037dc223f3e3474304dbb464a86423fa6c6db";

        Sm4Gcm decryptor = this.template.copyToDecryptor();
        String decrypted = decryptor.decrypt(encrypted);

        Assertions.assertEquals(
            data,
            decrypted,
            "original value is not equal to the expected value after decryption!"
        );
    }

}
