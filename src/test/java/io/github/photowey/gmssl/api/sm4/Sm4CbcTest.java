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
 * {@code Sm4CbcTest}
 *
 * @author weichangjun
 * @version 1.0.0
 * @since 2025/04/07
 */
@Slf4j
class Sm4CbcTest {

    private Sm4Cbc image;
    private byte[] key;
    private byte[] iv;

    @BeforeEach
    void init() {
        this.key = new byte[] {
            -73, -55, -122, -95,
            0, -4, 51, -38,
            125, -31, 38, 12,
            112, 8, -50, -92
        };
        this.iv = new byte[] {
            88, 121, -51, 88,
            32, -85, 98, 56,
            108, 18, 102, -73,
            -122, -59, -97, -25
        };

        this.image = new Sm4Cbc(this.key, this.iv, true, false);
    }

    @Test
    void testEncrypt_v1() {
        String data = "gmssl";

        Sm4Cbc encryptor = this.image.copyToEncryptor();
        String cipherHex = encryptor.encrypt(data);
        Assertions.assertNotNull(cipherHex, "data is empty exception!");

        // ccedec05b742098b33e0fc8c5c006365
        log.info("v1: the cipherHex is:{}", cipherHex);
    }

    @Test
    void testEncrypt_v2() {
        String data = "gmssl";

        byte[] plaintext = data.getBytes();
        byte[] ciphertext = new byte[plaintext.length + Sm4Cbc.BLOCK_SIZE];

        Sm4Cbc encryptor = this.image.copyToEncryptor();

        int cipherLen = encryptor.update(plaintext, 0, plaintext.length, ciphertext, 0);
        cipherLen += encryptor.doFinal(ciphertext, cipherLen);
        byte[] ciphertext1 = Arrays.copyOfRange(ciphertext, 0, cipherLen);

        String cipherHex = Bytes.toHex(ciphertext1);
        Assertions.assertNotNull(cipherHex, "data is empty exception!");

        // ccedec05b742098b33e0fc8c5c006365
        log.info("v2: the cipherHex is:{}", cipherHex);
    }

    @Test
    public void testDecrypt_v1() {
        String cipherHex = "ccedec05b742098b33e0fc8c5c006365";

        Sm4Cbc decryptor = this.image.copyToDecryptor();
        String plaintextStr = decryptor.decrypt(cipherHex);

        Assertions.assertEquals(
            "gmssl",
            plaintextStr,
            "original value is not equal to the expected value after decryption!"
        );
    }

    @Test
    public void testDecrypt_v2() {
        String cipherHex = "ccedec05b742098b33e0fc8c5c006365";
        byte[] ciphertext = Bytes.toBytes(cipherHex);

        Sm4Cbc decryptor = this.image.copyToDecryptor();

        byte[] decrypted = new byte[ciphertext.length + Sm4Cbc.BLOCK_SIZE];
        int decryptedOffset = 0;
        int decryptedLen;
        int ciphertextOffset = 0;
        decryptedLen = decryptor.update(
            ciphertext, ciphertextOffset, ciphertext.length, decrypted, decryptedOffset);
        decryptedOffset += decryptedLen;
        decryptedLen += decryptor.doFinal(decrypted, decryptedOffset);
        byte[] plaintext = Arrays.copyOfRange(decrypted, 0, decryptedLen);
        String plaintextStr = new String(plaintext);

        Assertions.assertEquals(
            "gmssl",
            plaintextStr,
            "original value is not equal to the expected value after decryption!"
        );
    }

}
