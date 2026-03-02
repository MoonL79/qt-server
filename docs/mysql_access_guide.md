# MySQL 访问文档

本文档提供一套可直接执行的流程，用于在 `192.168.14.133` 上创建新 MySQL 用户并完成数据库连接。

## 1. 服务器信息

- 主机：`192.168.14.133`
- 端口：`3306`
- 推荐认证插件：`caching_sha2_password`

## 2. 创建数据库与用户（在 MySQL 服务器上执行）

先使用管理员账号登录：

```bash
mysql -u root -p
```

创建数据库：

```sql
CREATE DATABASE IF NOT EXISTS app_db
  DEFAULT CHARACTER SET utf8mb4
  COLLATE utf8mb4_0900_ai_ci;
```

创建用户：

```sql
CREATE USER IF NOT EXISTS 'app_user'@'%'
IDENTIFIED WITH caching_sha2_password BY 'StrongPass_2026!';
```

授予权限：

```sql
GRANT ALL PRIVILEGES ON app_db.* TO 'app_user'@'%';
FLUSH PRIVILEGES;
```

验证结果：

```sql
SHOW GRANTS FOR 'app_user'@'%';
SELECT user, host, plugin FROM mysql.user WHERE user='app_user';
```

## 3. 客户端连接

在客户端执行：

```bash
mysql -h 192.168.14.133 -P 3306 -u app_user -p app_db
```

输入密码后执行：

```sql
SELECT DATABASE(), CURRENT_USER(), NOW();
```

若返回一行结果，说明连接成功。

## 4. 可选安全加固

如果你知道客户端固定 IP，建议把 `%` 改成具体 IP（更安全）：

```sql
CREATE USER 'app_user'@'192.168.14.50'
IDENTIFIED WITH caching_sha2_password BY 'StrongPass_2026!';
GRANT ALL PRIVILEGES ON app_db.* TO 'app_user'@'192.168.14.50';
FLUSH PRIVILEGES;
```

## 5. 常见错误与处理

### 错误：`ERROR 2059 ... mysql_native_password cannot be loaded`

原因：客户端与服务端账号认证插件不匹配（MySQL 9 客户端连接旧插件账号时常见）。

处理：

```sql
ALTER USER 'app_user'@'%' IDENTIFIED WITH caching_sha2_password BY 'StrongPass_2026!';
FLUSH PRIVILEGES;
```

### 错误：`Access denied for user`

检查项：

- 用户名和密码是否正确。
- 主机授权是否匹配你的客户端 IP（`'user'@'%'` 或指定 IP）。
- 是否已授权到正确数据库。

### 错误：连接超时或拒绝连接

检查项：

- MySQL 服务是否在服务器上运行。
- 防火墙/安全组是否放通 `3306` 端口。
- MySQL `bind-address` 是否允许远程访问。

## 6. 连接配置模板（按需替换）

```text
MYSQL_HOST=192.168.14.133
MYSQL_PORT=3306
MYSQL_DATABASE=app_db
MYSQL_USER=app_user
MYSQL_PASSWORD=StrongPass_2026!
```

## 7. 快速检查清单

- [ ] `Test-NetConnection 192.168.14.133 -Port 3306` 返回 `TcpTestSucceeded=True`
- [ ] 用户认证插件为 `caching_sha2_password`
- [ ] `SHOW GRANTS` 中包含 `app_db.*`
- [ ] 客户端命令 `mysql -h 192.168.14.133 -P 3306 -u app_user -p app_db` 可成功连接
