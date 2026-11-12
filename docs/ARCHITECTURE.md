# 架构与接口

## 数据流

```text
浏览器（原生 HTML/CSS/JS）
  │ 同源 JSON + HttpOnly 会话 Cookie
  │ 写操作附带 X-CSRF-Token
  ▼
Python ThreadingHTTPServer
  ├─ 输入验证 / 用户认证 / 会话 / 限流
  ├─ 参数化 SQL + user_id 过滤
  └─ scrypt 派生 / AES-256-GCM 加解密
       ▼
SQLite（用户验证值、盐、加密条目、最小化审计）
```

默认链路仅在本机回环地址使用 HTTP。浏览器显示条目时会收到明文；服务器和浏览器的内存都可能暂存秘密，因此不是端到端或零知识设计。

## 认证与加密

每个用户有两个独立的 16 字节随机盐。认证验证值与保险库密钥分别由主密码通过 scrypt 派生，参数为 N=16384、r=8、p=5、输出 32 字节。验证值及盐写入数据库；主密码和保险库密钥不写入数据库。比较验证值使用 hmac.compare_digest。

条目的 site、account、password、url、notes 序列化成一个 JSON 对象，使用 AES-256-GCM 加密。每次创建或修改生成新的 12 字节随机 nonce。AAD 为 `keynest:v3:<user_id>:<entry_id>`，绑定归属和条目身份。认证失败返回完整性异常，不把未认证的内容作为条目展示。

数据格式沿用课程修复版的 v3 标识；产品版本 3.1 不代表数据库格式已变更。当前没有自动迁移框架。

## 表结构

| 表 | 主要字段 | 说明 |
| --- | --- | --- |
| users | username, password_hash, auth_salt, vault_salt | 用户名大小写不敏感；不存明文主密码 |
| vault_entries | id, user_id, encrypted_blob, nonce, created_at, updated_at | 内容加密；标识、归属和时间为明文 |
| audit_logs | user_id, action, entry_id, detail, created_at | 记录操作类别，不记录条目正文 |

SQLite 使用外键和 WAL；查询按 user_id 约束，更新/删除同时匹配条目 ID 和用户 ID。

## 会话与前端锁定

服务端会话 token 使用 32 随机字节生成；CSRF token 使用 24 随机字节生成。会话 Cookie 为 HttpOnly、SameSite=Strict、Path=/；可配置 Secure。登录和注册会轮换浏览器当前会话，注销删除它。服务端有效请求续期为 30 分钟，并同步 Cookie；服务循环清理过期会话及旧限流状态。

前端会在本地无交互达到 30 分钟、估计的服务端会话期限到达、401 或手动锁定时清理条目、CSRF、编辑表单及审计 DOM。请求世代编号阻止旧异步响应重新填充数据。离开页面也会清除本地敏感状态；浏览器后台暂停定时器时，到恢复可见后再检查期限，不能保证后台计时器准点执行。

释放引用并不是保证物理内存清零；系统剪贴板不由本项目清除。锁定的网络请求若失败，服务端会话可能仍存续到过期。

## HTTP 接口

| 方法与路径 | 认证 | 作用 |
| --- | --- | --- |
| GET /api/session | 可匿名 | 查询登录状态与当前 CSRF token |
| POST /api/register | 匿名 | 注册并登录 |
| POST /api/login | 匿名 | 登录并轮换当前会话 |
| POST /api/logout | 会话 + CSRF | 注销 |
| GET /api/entries | 会话 | 当前用户的解密条目 |
| POST /api/entries | 会话 + CSRF | 创建条目 |
| PUT /api/entries/{uuid} | 会话 + CSRF | 修改本人条目 |
| DELETE /api/entries/{uuid} | 会话 + CSRF | 删除本人条目 |
| GET /api/audit | 会话 | 当前用户最近 50 条审计 |

JSON 写请求使用 `Content-Type: application/json`，请求体上限 64 KiB。字段须为字符串；site/account/password 必填，长度上限分别为 100/200/512，url 为 500、notes 为 1000。网址仅接受有效的 http/https 地址。接口验证权限，前端按钮显隐不是安全边界。

错误使用 400（输入）、401（会话）、403（CSRF）、404（不存在或不属于本人）、409（密文完整性异常）、429（登录限流）等状态；不应依赖错误文本作为稳定 API。项目尚未承诺长期 API 兼容性。
