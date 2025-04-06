@REM
@REM Copyright © 2025 the original author or authors.
@REM
@REM Licensed under the Apache License, Version 2.0 (the "License");
@REM you may not use this file except in compliance with the License.
@REM You may obtain a copy of the License at
@REM
@REM     http://www.apache.org/licenses/LICENSE-2.0
@REM
@REM Unless required by applicable law or agreed to in writing, software
@REM distributed under the License is distributed on an "AS IS" BASIS,
@REM WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
@REM See the License for the specific language governing permissions and
@REM limitations under the License.
@REM

@echo off
echo Installing pre-commit hook...

::
:: @author weichangjun
:: @version 1.0.0
:: @since 2025/04/04
::

set source=scripts\pre-commit
set target=.git\hooks\pre-commit

if not exist "%source%" (
    echo Source file "%source%" does not exist.
    exit /b 1
)

if not exist ".git\hooks" (
    echo Creating .git\hooks directory...
    mkdir ".git\hooks"
)

copy /Y "%source%" "%target%"
if %errorlevel% neq 0 (
    echo Failed to copy pre-commit script.
    exit /b 1
)

echo Pre-commit hook installed successfully.

exit /b 0
