SHELL := /bin/bash

# ----------------------------------------------------------------

# 默认使用 mvn, 如果 MVND_HOME 环境变量存在, 则使用 mvnd
MVN ?= $(if $(MVND_HOME),mvnd,mvn)

.PHONY: clean compile compile_local compile_dev compile_prod install test deploy package tree prepare perform check gitconf

# 设置默认目标
.DEFAULT_GOAL := help

# ----------------------------------------------------------------

# 打印当前目录
dir:
	@echo "Current directory: $(CURDIR)"

# ----------------------------------------------------------------

# 清理项目
clean: dir
	@echo "Cleaning the project..."
	$(MVN) clean

# ----------------------------------------------------------------

# 编译项目
compile: clean
	@echo "Using $(MVN) to compile the project..."
	$(MVN) compile

# ----------------------------------------------------------------

# 编译项目 local 环境
compile_local: clean
	@echo "Using $(MVN) to compile the project with profile local..."
	$(MVN) compile -Plocal

# 编译项目 dev 环境
compile_dev: clean
	@echo "Using $(MVN) to compile the project with profile dev..."
	$(MVN) compile -Pdev

# 编译项目 prod 环境
compile_prod: clean
	@echo "Using $(MVN) to compile the project with profile prod..."
	$(MVN) compile -Pprod

# ----------------------------------------------------------------

# 安装测试
install: clean
	@echo "Using $(MVN) to install the project..."
	$(MVN) install

# ----------------------------------------------------------------

# 运行测试
test: clean
	@echo "Using $(MVN) to test the project..."
	$(MVN) test

# 部署项目
deploy: clean
	@echo "Using $(MVN) to deploy the project..."
	$(MVN) -DskipTests=true source:jar deploy

# 打包项目
package: clean
	@echo "Using $(MVN) to package the project..."
	$(MVN) -DskipTests=true package

# 查看依赖树
tree:
	@echo "Using $(MVN) to show dependency tree..."
	$(MVN) dependency:tree -Dincludes=$(filter-out $@,$(MAKECMDGOALS))

# ----------------------------------------------------------------

# 生成文档
docs:
	@echo "Using $(MVN) to generate html docs of the project..."
	$(MVN) -Dfile.encoding=UTF-8 smart-doc:html

# ----------------------------------------------------------------

prepare: clean
	@echo "Using $(MVN) to release:prepare the project..."
	$(MVN) release:prepare

# 打包项目
perform:
	@echo "Using $(MVN) to release:perform the project..."
	$(MVN) release:perform

# ----------------------------------------------------------------

# Checkstyle 检查
check:
	@echo "Using $(MVN) to checkstyle:check the project..."
	$(MVN) checkstyle:check

# ----------------------------------------------------------------

name?=Your Name
email?=you@example.com

# 定义 gitconf 目标来设置 Git 用户名和邮箱
gitconf:
	@echo "Git user.name and user.email have been set globally."
	git config user.name "$(name)"
	git config user.email "$(email)"

# ----------------------------------------------------------------

# 帮助信息
help:
	@echo "Available targets:"
	@echo "  clean     - Clean the project"
	@echo "  compile   - Compile the project"
	@echo "  test      - Run tests"
	@echo "  deploy    - Deploy the project"
	@echo "  package   - Package the project"
	@echo "  tree      - Show dependency tree (e.g., make tree group:artifact | :artifact)"
	@echo "  docs      - Generate the html documents of web project"
	@echo "  prepare   - Release:prepare the project"
	@echo "  perform   - Release:perform the project"
	@echo "  check     - Checkstyle:check the project"
	@echo "  gitconf   - Git:config git user.name and user.email of the project"
	@echo "  help      - Show this help message"

# ----------------------------------------------------------------

# 处理未知目标
%:
	@echo "Unknown target: $@"
	@echo "Use 'make help' to see available targets."
