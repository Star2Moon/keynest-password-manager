# 第三方组件说明

本仓库不将第三方库源码打包进项目，安装依赖时应保留其各自许可证。下列链接用于查看上游的许可与来源；本项目的 MIT 许可不替代它们。

| 组件 | 用途 | 上游许可/来源 |
| --- | --- | --- |
| Python / 标准库 | HTTP、SQLite、scrypt、测试 | [Python 许可证](https://docs.python.org/3/license.html) |
| cryptography | AES-GCM | [pyca/cryptography](https://github.com/pyca/cryptography)（Apache-2.0 / BSD-3-Clause，详见上游） |
| Bandit | 开发阶段静态扫描 | [PyCQA/bandit](https://github.com/PyCQA/bandit)（Apache-2.0） |
| Node.js | 前端测试运行时 | [Node.js LICENSE](https://github.com/nodejs/node/blob/main/LICENSE)（含第三方许可说明） |

前端使用系统字体，没有外部 CDN 脚本、在线字体或 npm 运行依赖。GitHub Actions 使用官方 actions/checkout、setup-python、setup-node 工作流组件；其许可证见对应上游仓库。
