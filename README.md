# KeyNest 密钥巢

[![CI](https://github.com/Star2Moon/keynest-password-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/Star2Moon/keynest-password-manager/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

一个用于学习和本机演示的开源密码管理器。以 Python、SQLite 和原生 JavaScript 实现，便于阅读从登录认证到保险库加密的完整流程。

> **安全定位：教学项目，不是经过独立审计的生产级密码管理器。请使用虚构数据，不要保存真实重要密码，也不要直接暴露到公网。服务端能够访问解密密钥，本项目不是零知识架构。**

## 功能

- 用户注册与登录；主密码使用独立随机盐的 scrypt 派生验证。
- 密码记录新增、编辑、删除、搜索、隐藏/显示与复制。
- 浏览器 Web Crypto 生成 20 位随机密码。
- 网站、账号、密码、网址、备注作为整体使用 AES-256-GCM 认证加密存储。
- 参数化 SQL、按用户隔离、CSRF 校验、登录失败限流和安全响应头。
- 最近 50 条操作审计；日志不记录密码和条目正文。
- 手动锁定、401 响应锁定和 30 分钟本地闲置锁定；锁定时清理前端状态与敏感表单。

## 界面预览

![KeyNest 3.1 保险库界面，数据均为虚构演示数据](docs/images/vault.png)

截图来自本地运行的 3.1 版本，仅使用虚构演示账号，密码默认隐藏。

## 快速开始

需要 **Python 3.10 或更高版本**。建议使用独立虚拟环境。Node.js 仅用于运行前端测试，不是运行依赖。

```bash
git clone https://github.com/Star2Moon/keynest-password-manager.git
cd keynest-password-manager
python -m venv .venv
```

Windows PowerShell：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

macOS / Linux：

```bash
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python app.py
```

打开 **http://127.0.0.1:8080**，自行注册测试账号。用户名为 3–32 位字母、数字或下划线；主密码为 12–128 位，至少包含小写字母、大写字母、数字、其他字符中的三类。项目没有默认账号或后门密码。

Windows 安装依赖后也可以双击 `run.bat`，或运行 `.\run.ps1`。按 Ctrl+C 停止服务。首次启动自动创建 `data/vault_v3.db`；数据库不会提交到 Git。

**主密码不能找回，当前也没有主密码修改、云同步、导入导出或恢复功能。** 请勿把这个演示程序作为重要数据的唯一存储位置。

## 开发与测试

以下命令中的 `python` 应指向已激活的虚拟环境，或替换为上述虚拟环境 Python 的完整路径。

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
node --test tests/frontend.test.cjs
python -m bandit -r app.py
```

前端测试需要 Node.js 20+，只使用内置模块，无需 npm install。GitHub Actions 会在 Windows / Linux 的 Python 3.10、3.13 环境中执行测试，并运行前端回归与静态安全扫描。测试使用临时数据库和虚构凭据。

具体覆盖范围和未覆盖风险见 [测试说明](docs/TESTING.md)。自动测试通过不等于没有漏洞或可以投入生产。

## 配置

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PM_HOST` | `127.0.0.1` | 绑定地址，保持仅本机访问 |
| `PM_PORT` | `8080` | HTTP 端口 |
| `PM_DB_PATH` | 项目目录下 `data/vault_v3.db` | SQLite 数据库路径，建议使用绝对路径 |
| `PM_SECURE_COOKIE` | `0` | 设为 `1` 时仅通过 HTTPS 发送会话 Cookie |

配置从进程环境读取，**不会自动加载 .env 文件**。把 Secure Cookie 设为 1 不会让服务自动支持 HTTPS，也不会使它成为生产级服务。详见 [运行与数据管理](docs/DEPLOYMENT.md)。

## 设计与限制

认证盐和保险库盐相互独立；每次保存条目使用新的 12 字节 nonce，附加认证数据绑定用户 ID 与条目 ID。服务端会话保存解密密钥，并在注销、过期或进程重启后释放引用。

这保护的是数据库静态内容，不防御已被控制的服务器、操作系统、浏览器扩展、键盘记录器或剪贴板窃取。Python/JavaScript 运行时无法保证字符串或密钥物理内存清零；隐藏密码也不表示明文不在内存中。用户名、用户 ID、记录数量和时间戳等元数据仍为明文。

详细说明：[架构与接口](docs/ARCHITECTURE.md) · [安全策略](SECURITY.md)

## 项目结构

```text
keynest-password-manager/
├── app.py                    # HTTP、认证、会话、加密及数据库逻辑
├── static/                   # 原生 HTML/CSS/JavaScript 界面
├── tests/                    # 功能、安全、真实 HTTP 和前端行为回归
├── docs/                     # 架构、部署、测试和开源协作说明
├── .github/                  # 自动测试、Issue / PR 模板
├── requirements.txt
├── requirements-dev.txt
├── CONTRIBUTING.md
├── SECURITY.md
└── LICENSE
```

## 参与贡献

欢迎提交可复现的问题、测试、文档和功能改进。请先阅读 [贡献指南](CONTRIBUTING.md)，通过 Issue → Fork → 分支 → Pull Request → Review → Merge 参与。

项目发起人：杨皓嘉（[@Star2Moon](https://github.com/Star2Moon)）。项目源于网络空间安全课程实践；本公开版本基于课程修复版整理，并使用 AI 辅助代码、测试和文档工作。发布版本为 **3.1.0**；早期故意带缺陷的教学版本、私人录音、课程报告和个人学号不包含在本仓库中。

课程/开源活动参与者可参考 [开源协作与成果记录](docs/OPEN_SOURCE.md)。贡献人数、合并记录、Stars 与下载量以平台真实记录为准。

## 许可证与致谢

本项目使用 [MIT License](LICENSE)。第三方组件遵循各自许可证，见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。版本变化见 [CHANGELOG.md](CHANGELOG.md)。
