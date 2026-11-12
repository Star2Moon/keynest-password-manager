# 测试说明

## 执行

在仓库根目录使用虚拟环境 Python：

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
node --test tests/frontend.test.cjs
python -m bandit -r app.py
```

Node.js 需要 20+；前端测试只使用内置 node:test、vm 等模块。HTTP 测试会在 127.0.0.1 的临时端口启动服务并自动关闭；若运行环境禁止本机网络绑定，需允许回环测试，不能将权限失败当作测试通过。

## 覆盖范围

| 测试文件 | 验证对象 |
| --- | --- |
| test_functional.py | 注册/登录、CRUD、跨用户修改删除隔离、会话及随机生成器入口 |
| test_security.py | 随机盐、无明文落库、AES-GCM 篡改检测、SQL 注入、输入约束、CSRF、会话清理、限流、安全头 |
| test_http.py | 真实 HTTP 路由、Cookie/轮换/注销、CSRF、用户隔离、CRUD、请求 framing、UTF-8、长度限制、限流 |
| frontend.test.cjs | 锁定后清空状态/DOM/表单、迟到响应隔离、401、计时、编辑器清理、密码生成 |

测试使用虚构凭据和临时数据库；测试代码里的密码不是可用账号。任何新修改都应重新运行测试，历史报告不能替代当前版本结果。

## CI

GitHub Actions 工作流位于 .github/workflows/ci.yml：

- Ubuntu / Windows，Python 3.10 / 3.13：安装运行依赖并运行 Python + HTTP 回归。
- Ubuntu，Node.js 22：前端行为回归。
- Ubuntu，Python 3.13：Bandit 静态扫描。

CI Badge 反映最近工作流状态；提交后应等待当前提交的所有检查结束，而不是仅看旧的绿色结果。

## 人工验收建议

1. 在本机启动，注册一个全新测试用户。
2. 使用 example.test 虚构账号创建、编辑、搜索、显示/隐藏和复制密码。
3. 注销并重新登录，检查条目保持。
4. 用另一个测试账号确认看不到第一位用户条目。
5. 打开编辑弹窗后锁定，确认弹窗关闭、表单清空；浏览器后退/恢复不应显示旧秘密。
6. 检查窄屏、键盘操作、错误提示和剪贴板权限失败时的行为。

## 未覆盖与限制

Node 测试使用轻量 DOM 替身，不是跨浏览器真实端到端测试。当前自动化不能证明物理内存擦除、浏览器扩展安全、完整无障碍兼容、抗拒绝服务、依赖供应链安全或生产级密码学正确性。Bandit 未报告问题也不等于没有漏洞。

性能负载、持续模糊测试、备份恢复、数据库迁移和完整浏览器矩阵属于后续工作。这里不虚构覆盖率或独立审计结论。
