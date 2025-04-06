# `gmssl-sdk-java`

> `gmssl-sdk-java` `C` 绑定库

```shell
# 生成: `io_github_photowey_gmssl_jni_GmSSLJNI.h`
$ cd ./src/main/java/io/github/photowey/gmssl/jni
$ javac -h . GmSSLJNI.java
```



修改点

- `.h` 文件直接通过命令行生存

- `.c` 文件中所有绑定的函数名称均添加 `0`  结尾
  - `rand_bytes`
    - `rand_bytes0`
    - `Java_io_github_photowey_gmssl_jni_GmSSLJNI_rand_1bytes0`

