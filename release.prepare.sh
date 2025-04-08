#!/usr/bin/env bash
#
# Copyright © 2025 the original author or authors.
# Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


# 设置 UTF-8 编码
export LANG=en_US.UTF-8

# 获取当前目录并打印
CURRENT_DIR=$(pwd)
echo "Current directory: $CURRENT_DIR"

# 默认使用 mvn 命令
CMD="mvn"

# 检查 MVND_HOME 是否设置
if [ -n "$MVND_HOME" ]; then
    echo "Using mvnd from: $MVND_HOME"
    CMD="$MVND_HOME/bin/mvnd"
fi

# 执行 Maven 命令
$CMD release:perform

# 检查命令执行结果
# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
    # shellcheck disable=SC2319
    echo "Maven command failed with error code $?"
else
    echo "Maven command completed successfully"
fi
