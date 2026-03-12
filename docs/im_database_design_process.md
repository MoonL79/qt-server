# IM 数据库表设计流程（MySQL）

本文档记录本项目 IM 服务端数据库从 0 到可用的完整设计与落地流程，包含设计原则、执行顺序、SQL 示例与最终表结构说明。

## 1. 目标与设计原则

### 1.1 目标

- 支撑 IM 场景下的账号、会话、成员、消息、送达回执、好友关系、设备会话管理。
- 支持“单聊与群聊统一建模”，通过会话唯一标识区分。
- 优先保证服务端实现简单、扩展平滑、索引可控。

### 1.2 关键原则

- 单聊和群聊统一使用同一套会话表与消息表。
- 所有业务数据通过主键与唯一键保证一致性。
- 高并发查询路径必须有索引（按会话拉消息、按用户查会话、按用户查送达状态）。
- 账号表与 IM 扩展资料分离，降低历史兼容风险。
- 回执仅保留“送达”，不做已读/未读状态。

## 2. 连接与环境验证

### 2.1 服务器信息

- MySQL Host: `192.168.14.133`
- Port: `3306`
- Database: `app_db`

### 2.2 连接验证步骤

1. 验证端口连通（在客户端机器）：

```powershell
Test-NetConnection 192.168.14.133 -Port 3306
```

2. 验证客户端可连接：

```bash
mysql -h 192.168.14.133 -P 3306 -u app_user -p app_db
```

3. 验证查询：

```sql
SELECT 1 AS ok;
```

## 3. 建库与建用户（初始化）

在 MySQL 管理员账号下执行：

```sql
CREATE DATABASE IF NOT EXISTS app_db
  DEFAULT CHARACTER SET utf8mb4
  COLLATE utf8mb4_0900_ai_ci;

CREATE USER IF NOT EXISTS 'app_user'@'%'
IDENTIFIED WITH caching_sha2_password BY '123456';

GRANT ALL PRIVILEGES ON app_db.* TO 'app_user'@'%';
FLUSH PRIVILEGES;
```

说明：

- 选择 `caching_sha2_password`，避免部分客户端出现 `mysql_native_password` 兼容问题。

## 4. 分阶段建表流程

### 4.1 第一阶段：基础账号表

先创建基础用户表 `user_data`（已落地）：

```sql
CREATE TABLE IF NOT EXISTS user_data (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(64) NOT NULL,
  email VARCHAR(128) NOT NULL,
  phone VARCHAR(32) NULL,
  password_hash VARCHAR(255) NOT NULL,
  status TINYINT UNSIGNED NOT NULL DEFAULT 1,
  last_login_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_user_data_username (username),
  UNIQUE KEY uk_user_data_email (email),
  KEY idx_user_data_status (status),
  KEY idx_user_data_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
```

### 4.2 第二阶段：IM 核心模型

在 `user_data` 基础上新增 IM 相关表：

1. `user_im_profile`：IM 用户扩展资料  
2. `conversations`：统一会话（单聊/群聊）  
3. `conversation_members`：会话成员关系  
4. `messages`：消息主表  
5. `message_receipts`：消息送达回执  
6. `friendships`：好友关系  
7. `user_sessions`：设备会话/Token 会话

### 4.3 第三阶段：回执模型简化

按业务要求“只关心送达，不关心已读”，对 `message_receipts` 做调整：

- 删除 `read_at`
- 索引从 `(user_id, read_at)` 调整为 `(user_id, delivered_at)`

## 5. 最终表结构（已落地）

### 5.1 user_data（基础账号）

- 主键：`id`
- 对外数字标识：`numeric_id`（`INT UNSIGNED`，唯一，从 `10000` 开始，按注册顺序递增）
- 唯一：`username`、`email`
- 状态与时间：`status`、`last_login_at`、`created_at`、`updated_at`

建议迁移（兼容现有 `id` 主键与外键）：

```sql
ALTER TABLE user_data
  ADD COLUMN numeric_id INT UNSIGNED NULL;

UPDATE user_data
SET numeric_id = CAST(id + 9999 AS UNSIGNED)
WHERE numeric_id IS NULL;

ALTER TABLE user_data
  ADD UNIQUE KEY uk_user_data_numeric_id (numeric_id);
```

### 5.2 user_im_profile（IM 扩展资料）

- 主键：`user_id`（外键到 `user_data.id`）
- 唯一：`user_uuid`（对外标识）
- 资料：`nickname`、`avatar_url`、`bio`、`gender`、`birthday`、`region`
- 在线状态：`is_online`、`last_seen_at`
- 扩展：`extra`（JSON）

### 5.3 conversations（统一会话）

- 主键：`id`
- 唯一：`conversation_uuid`
- 会话属性：`type`（1 单聊，2 群聊）、`name`、`owner_user_id`、`notice`
- 时间：`created_at`、`updated_at`

说明：

- 单聊与群聊不分表，统一通过 `conversation_uuid` 路由，`type` 作为元数据。

### 5.4 conversation_members（会话成员）

- 主键：`id`
- 唯一：`(conversation_id, user_id)`
- 成员属性：`role`、`mute_until`
- 游标：`last_read_message_id`（可保留为客户端拉取游标，不代表已读回执）

### 5.5 messages（消息）

- 主键：`id`
- 唯一：`message_uuid`
- 强约束：`(conversation_id, seq)` 唯一（会话内顺序唯一）
- 幂等：`(conversation_id, sender_user_id, client_msg_id)` 唯一
- 内容：`message_type`、`content`（JSON）
- 生命周期：`created_at`、`edited_at`、`deleted_at`

### 5.6 message_receipts（仅送达回执）

- 联合主键：`(message_id, user_id)`
- 字段：`delivered_at`
- 语义：`delivered_at IS NULL` 表示未送达，非空表示已送达

### 5.7 friendships（好友关系）

- 联合主键：`(user_id, friend_user_id)`
- 状态：`status`（0 申请中，1 已通过，2 已拉黑）
- 备注：`remark`

### 5.8 user_sessions（设备会话）

- 主键：`id`
- 唯一：`access_token_hash`、`(user_id, device_id)`
- 会话信息：`platform`、`ip`、`user_agent`
- 生命周期：`last_active_at`、`expires_at`、`revoked_at`

## 6. 核心设计决策说明

### 6.1 为什么单聊/群聊统一建模

- 服务端消息分发逻辑只认会话 ID，代码路径更一致。
- 一套消息表支持全部会话类型，避免跨表查询和迁移复杂度。
- 后续扩展“频道/临时会话”等类型时，成本更低。

### 6.2 为什么把 IM 资料独立成 user_im_profile

- 避免直接改动已有 `user_data` 造成版本兼容问题。
- 可以在不影响登录域模型的情况下独立演进 IM 字段。

### 6.3 为什么消息内容使用 JSON

- 兼容文本、图片、语音、文件、系统消息等异构结构。
- 减少频繁 DDL 变更。

## 7. 建议的上线前检查

1. 执行 `SHOW TABLES;`，确认 8 张核心表均存在。  
2. 检查外键是否生效（`SHOW CREATE TABLE`）。  
3. 验证唯一键冲突行为（重复 `client_msg_id`、重复 `conversation_id+seq`）。  
4. 压测以下查询路径：
- 按会话分页拉消息：`messages (conversation_id, created_at)`
- 按用户查会话：`conversation_members (user_id, conversation_id)`
- 按用户查送达：`message_receipts (user_id, delivered_at)`

## 8. 后续可选增强

- 增加会话未读计数字段与异步聚合任务。
- 增加消息撤回状态与撤回审计。
- 增加多端同步游标表（按设备维度）。
- 增加分库分表方案（按 `conversation_id` 或时间分片）。
