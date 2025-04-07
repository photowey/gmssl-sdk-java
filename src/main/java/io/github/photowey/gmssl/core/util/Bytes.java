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
package io.github.photowey.gmssl.core.util;

import java.nio.charset.StandardCharsets;

import io.github.photowey.gmssl.core.thrower.AssertionErrorThrower;

/**
 * {@code Bytes}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/07
 */
public final class Bytes {

    private static final char[] HEX_CHARS = {
        '0', '1', '2', '3', '4', '5',
        '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    private Bytes() {
        AssertionErrorThrower.throwz(Bytes.class);
    }

    public static String toHex(String input) {
        return byteToHex(input.getBytes(StandardCharsets.UTF_8));
    }

    public static String toHex(byte[] input) {
        return byteToHex(input);
    }

    // ----------------------------------------------------------------

    public static byte[] toBytes(String hex) {
        return hexToBytes(hex);
    }

    public static String toOriginal(String hex) {
        byte[] bytes = hexToBytes(hex);

        return new String(bytes, StandardCharsets.UTF_8);
    }

    // ----------------------------------------------------------------

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        if (len % 2 != 0) {
            throw new IllegalArgumentException("Hex: invalid hex data length");
        }

        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] =
                (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return bytes;
    }

    private static String byteToHex(byte[] input) {
        StringBuilder buf = new StringBuilder();
        for (byte b : input) {
            buf.append(HEX_CHARS[(b >>> 4) & 0x0f]);
            buf.append(HEX_CHARS[b & 0x0f]);
        }

        return buf.toString();
    }
}
