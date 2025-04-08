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

import io.github.photowey.gmssl.core.util.Bytes;

/**
 * {@code Random}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/06
 */
public interface Random {

    /**
     * 生成随机字符串
     * |- 随机字符串长度为指定字节长度的 2 倍
     *
     * @param len 随机字节长度
     * @return 随机字节转 16 进制字符串
     */
    default String rand(int len) {
        return Bytes.toHex(this.randBytes(len));
    }

    default String rand(int offset, int len) {
        byte[] out = new byte[len];
        this.randBytes(out, offset, len);

        return Bytes.toHex(out);
    }

    default byte[] randBytes(int len) {
        byte[] out = new byte[len];
        this.randBytes(out, 0, len);

        return out;
    }

    void randBytes(byte[] out, int offset, int len);
}
