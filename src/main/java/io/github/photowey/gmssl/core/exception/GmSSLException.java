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
package io.github.photowey.gmssl.core.exception;

/**
 * {@code GmSSLException}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/06
 */
public class GmSSLException extends RuntimeException {

    public GmSSLException() {
        super();
    }

    public GmSSLException(String message, Object... args) {
        super(String.format(message, args));
    }

    public GmSSLException(Throwable cause, String message, Object... args) {
        super(String.format(message, args), cause);
    }

    public GmSSLException(Throwable cause) {
        super(cause);
    }

    protected GmSSLException(
        Throwable cause,
        boolean enableSuppression,
        boolean writableStackTrace,
        String message, Object... args) {
        super(String.format(message, args), cause, enableSuppression, writableStackTrace);
    }
}
