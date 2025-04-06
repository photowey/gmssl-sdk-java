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
package io.github.photowey.gmssl.core.loader;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Optional;

import io.github.photowey.gmssl.core.exception.GmSSLException;

/**
 * {@code GmSSLNativeLoader}.
 *
 * @author photowey
 * @version 3.1.1.1.0.0
 * @since 2025/04/06
 */
public class GmSSLNativeLoader {

    public static final String GMSSL_DYNAMIC_LIB_PATH_ENV_KEY = "GMSSL_DYNAMIC_LIB_PATH";
    public static final String GMSSL_DYNAMIC_LIB_PATH_PROPERTY_KEY = "gmssl.dynamic.lib.path";
    public static final String GMSSL_JNILIB_NAME = "libgmssljni";
    public static final String GMSSL_JNI_RESOURCE_LIB_PATH_PREFIX = "lib";
    public static final String MACOS_DEFAULT_GMSSL_LIB_PATH =
        "/usr/local/lib/libgmssl.3.dylib";

    /**
     * 直接加载本地库
     * |- 前提:
     * |- 1.设置 {@code java.library.path}
     * |- 2.设置 {@code LD_LIBRARY_PATH} 环境变量
     * |- |- 总之: {@code JVM} 能自动加载到的路径
     *
     * @param library 库名 libgmssljni:默认
     */
    public synchronized static void loadLibrary(String library) {
        // SET: java.library.path
        // SET: LD_LIBRARY_PATH
        checkReferencedLib();
        System.loadLibrary(library);
    }

    /**
     * 通过相对路径加载本地库
     * |- {@code JAR} 中的路径
     *
     * @param library 库名(不带扩展名)
     */
    public synchronized static void load(String library) {
        String resourceLibPath =
            GMSSL_JNI_RESOURCE_LIB_PATH_PREFIX + "/" + library + "." + libExtension();
        try (InputStream input = GmSSLNativeLoader.class.getClassLoader()
            .getResourceAsStream(resourceLibPath)) {
            if (null == input) {
                throw new GmSSLException(
                    "gmssl: Lib file:[%s] not found in jar.",
                    resourceLibPath
                );
            }

            Path tempFile = Files.createTempFile(library, "." + libExtension());
            tempFile.toFile().deleteOnExit();

            Files.copy(input, tempFile, StandardCopyOption.REPLACE_EXISTING);
            checkReferencedLib();
            System.load(tempFile.toAbsolutePath().toString());

            tempFile.toFile().deleteOnExit();
        } catch (Exception e) {
            throw new GmSSLException(
                "gmssl: Unable to load lib[%s] from jar",
                resourceLibPath
            );
        }
    }

    /**
     * Get the operating system type.
     *
     * @return operating system name
     */
    private static String osType() {
        String os = "unknown";
        String osName = System.getProperty("os.name").toLowerCase();
        if (osName.startsWith("windows")) {
            os = "win";
        }
        if (osName.startsWith("linux")) {
            if ("dalvik".equalsIgnoreCase(System.getProperty("java.vm.name"))) {
                os = "android";
                System.setProperty("jna.nounpack", "true");
            } else {
                os = "linux";
            }
        }
        if (osName.startsWith("mac os x") || osName.startsWith("darwin")) {
            os = "osx";
        }

        return os;
    }

    /**
     * Get the library extension name based on the operating system type.
     *
     * @return extension name
     */
    private static String libExtension() {
        String osType = osType();
        String libExtension = null;
        if ("win".equals(osType)) {
            libExtension = "dll";
        }
        if ("osx".equals(osType)) {
            libExtension = "dylib";
        }
        if ("linux".equals(osType)) {
            libExtension = "so";
        }

        return libExtension;
    }

    /**
     * In macOS systems, the execution of library calls relies on
     * loading gmssl.3.dylib from the installed gmssl library,
     * in order to correct the @rpath path issue. Alternatively,
     * you can manually execute the command:
     * "install_name_tool -change @rpath/libgmssl.3.dylib \
     * /usr/local/lib/libgmssl.3.dylib \
     * xxx/lib/libgmssljni.dylib" to fix the library reference path issue.
     * This has already been loaded and manual execution is unnecessary.
     */
    private static void checkReferencedLib() {
        String macReferencedLib = determineDynamicLibPathByEnvOrProperty();
        Optional<String> lib = Optional.ofNullable(macReferencedLib);
        if (lib.isPresent() && !lib.get().isEmpty()) {
            File libFile = new File(macReferencedLib);
            if (libFile.exists()) {
                System.load(macReferencedLib);
            }
        }
    }

    private static String determineDynamicLibPathByEnvOrProperty() {
        // /usr/local/lib/libgmssl.3.dylib
        String libPath = System.getenv(GMSSL_DYNAMIC_LIB_PATH_ENV_KEY);
        if (null == libPath || libPath.isEmpty()) {
            libPath = System.getProperty(GMSSL_DYNAMIC_LIB_PATH_PROPERTY_KEY);
        }

        return libPath;
    }
}
