# Speraymer LoginSystem

一个可直接嵌入 Python 应用的 SQLite 邮箱验证码登录组件，仅使用 Python 标准库。支持指定邮箱域名、一次性验证码、发送间隔、错误次数限制、用户创建、七天会话和退出登录。业务资料与数据表由宿主应用管理。

设计参考 [floating-sticky-todos](https://github.com/Speraymer/floating-sticky-todos) 的“先验证邮箱，再按用户身份访问数据”思路。参考项目实际使用 Firebase 邮箱密码认证与 Firestore `users/{uid}/workspace/current`，此组件为适配无需外部云服务的应用，采用邮箱验证码与 SQLite；它不提供跨设备同步或 Firebase 接口。

## 安装

将 [`login_system.py`](login_system.py) 放入 Python 项目的导入路径。无需第三方依赖。建议直接复制该文件并将版本固定在宿主仓库中，以便桌面打包。

## 使用

```python
import sqlite3
from login_system import AuthError, EmailCodeAuth, SCHEMA

db = sqlite3.connect('app.sqlite3', isolation_level=None)
db.row_factory = sqlite3.Row
db.execute('PRAGMA foreign_keys=ON')
db.executescript(SCHEMA)

auth = EmailCodeAuth(db, now=1720000000.0, domain='example.edu')

def send_email(address, code):
    # 在宿主应用中通过 SMTP 等通道发送。不要记录或返回生产验证码。
    ...

auth.issue_code({'email': 'student@example.edu'}, send_email)
# 验证请求到达后：
user_id = auth.verify_code({'email': 'student@example.edu', 'code': '123456'})
token = auth.sign_in(user_id)
# 将 token 放入 HttpOnly、SameSite Cookie；HTTPS 下还应设置 Secure。
user = auth.user_for_session(token)
auth.logout(token)
```

生产环境由宿主应用负责 HTTPS、Cookie 安全属性、CSRF/Origin 检查、SMTP 配置，以及将验证码和会话操作放入数据库事务。`demo=True` 会把验证码放进响应，仅用于本地演示。生产环境还应在 HTTP 层限制单个 IP 的请求速率；组件目前按邮箱限制发送间隔和验证次数。用户表只包含 `id`、`email`，可由宿主应用在建表时添加资料字段。外键依赖于每个数据库连接都启用 `PRAGMA foreign_keys=ON`。

## 数据库

| 表 | 用途 |
| --- | --- |
| `users` | 随机用户 ID、唯一邮箱；只在验证码通过后创建。 |
| `verification_codes` | 邮箱、验证码 SHA-256 摘要、到期时间、尝试次数。验证码十分钟有效，最多尝试五次。 |
| `sessions` | 会话令牌 SHA-256 摘要、用户 ID、到期时间。只向客户端传原始令牌。 |

验证失败次数会立即提交，因此宿主处理 `AuthError` 时回滚其他事务也不会重置次数。调用 `verify_code` 与 `sign_in` 应位于同一数据库事务中。时间值均为 Unix 秒。

运行测试：`python -m unittest discover -s tests -q`。

## Companion 接入

Companion 在 `companion/login_system.py` 固定此组件版本。原有 `/api/auth/code`、`/api/auth/verify`、`/api/auth/logout` 和 `companion_session` Cookie 保持不变。既有 SQLite 用户、会话与验证码表继续使用，无需迁移数据；用户资料、活动与申请仍在原数据库中按用户 ID 管理。
