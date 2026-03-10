# WebSocket 通信协议（V1）

## 1. 总体信封格式

客户端到服务端、服务端到客户端统一使用以下 JSON 文本帧：

```json
{
  "type": "AUTH | PROFILE | MESSAGE",
  "action": "枚举动作",
  "request_id": "uuid",
  "code": 0,
  "data": {}
}
```

字段规则：
- `type`: 必填，字符串，枚举：`AUTH`、`PROFILE`、`MESSAGE`
- `action`: 必填，字符串，且必须属于对应 `type` 的动作枚举
- `request_id`: 必填，字符串，建议 UUID，由请求方生成，响应方原样回传
- `code`: 状态码，响应必填；请求可省略或固定传 `0`（服务端忽略请求中的 `code`）
- `data`: 必填，对象，根据 `type + action` 使用不同结构

## 2. Action 枚举

### 2.1 AUTH
- `LOGIN`
- `REGISTER`
- `LOGOUT`
- `REFRESH_TOKEN`

### 2.2 PROFILE
- `GET`
- `GET_INFO`
- `SET_INFO`
- `UPDATE`
- `ADD_FRIEND`
- `DELETE_FRIEND`
- `LIST_FRIENDS`

### 2.3 MESSAGE
- `SEND`
- `PULL`
- `ACK`

## 3. 三类 data 格式

### 3.1 AUTH 的 data

1. `action = LOGIN`
```json
{
  "username": "string",
  "password": "string"
}
```

2. `action = LOGOUT`
```json
{
  "token": "string"
}
```

3. `action = REGISTER`
```json
{
  "username": "string, 必填，3~32，仅允许字母数字下划线",
  "email": "string, 必填，最大128，合法邮箱格式",
  "password": "string, 必填，8~64，且必须包含大小写字母和数字",
  "nickname": "string, 必填，1~64",
  "phone": "string, 可选，最大32",
  "avatar_url": "string, 可选，最大255",
  "bio": "string, 可选，最大255"
}
```

4. `action = REFRESH_TOKEN`
```json
{
  "refresh_token": "string"
}
```

### 3.2 PROFILE 的 data

1. `action = GET`
```json
{
  "numeric_id": "string, 必填，无符号整数字符串"
}
```

成功响应会在 `data.profile` 中返回用户信息：
```json
{
  "user_id": "string",
  "numeric_id": "string",
  "username": "string",
  "email": "string",
  "phone": "string",
  "status": 1,
  "user_uuid": "string",
  "nickname": "string",
  "avatar_url": "string",
  "bio": "string",
  "signature": "string",
  "theme": "string"
}
```

2. `action = GET_INFO`（个人信息请求）
```json
{
  "user_id": "string"
}
```

成功响应会在 `data.profile` 中返回个人信息：
```json
{
  "avatar_url": "string",
  "nickname": "string",
  "signature": "string",
  "theme": "string，未设置时默认 default"
}
```

3. `action = SET_INFO`（个人信息设置）
```json
{
  "user_id": "string",
  "avatar_url": "string, 必填，最大255",
  "nickname": "string, 必填，最大64",
  "signature": "string, 必填，最大255",
  "theme": "string, 可选，最大32"
}
```

成功响应会在 `data.profile` 回显保存后的个人信息：
```json
{
  "avatar_url": "string",
  "nickname": "string",
  "signature": "string",
  "theme": "string，若请求未传或为空则为 default"
}
```
说明：`signature/theme` 存储于 `user_im_profile.extra`（JSON）中。

4. `action = UPDATE`
```json
{
  "user_id": "string",
  "nickname": "string",
  "avatar_url": "string"
}
```

5. `action = ADD_FRIEND`
```json
{
  "user_numeric_id": "string, 必填，无符号整数字符串",
  "friend_numeric_id": "string, 必填，无符号整数字符串",
  "remark": "string, 可选，最大255"
}
```

成功响应会返回：
```json
{
  "user_numeric_id": "string",
  "friend_numeric_id": "string",
  "user_id": "string",
  "friend_user_id": "string",
  "status": 1
}
```

6. `action = DELETE_FRIEND`
```json
{
  "user_id": "string, 必填，无符号整数字符串",
  "friend_user_id": "string, 必填，无符号整数字符串"
}
```

7. `action = LIST_FRIENDS`
```json
{
  "numeric_id": "string, 必填，无符号整数字符串"
}
```

成功响应会返回：
```json
{
  "numeric_id": "string",
  "user_id": "string",
  "friends": [
    {
      "user_id": "string",
      "numeric_id": "string",
      "username": "string",
      "status": 1,
      "nickname": "string",
      "avatar_url": "string",
      "bio": "string"
    }
  ]
}
```

成功响应会返回：
```json
{
  "user_id": "string",
  "friend_user_id": "string",
  "removed": true
}
```

### 3.3 MESSAGE 的 data

1. `action = SEND`
```json
{
  "conversation_id": "string",
  "content": "string"
}
```

2. `action = PULL`
```json
{
  "conversation_id": "string"
}
```

3. `action = ACK`
```json
{
  "conversation_id": "string",
  "message_id": "string",
  "delivered": true
}
```

## 4. 响应格式

服务端响应仍使用同一信封结构：

```json
{
  "type": "与请求一致，异常时可能为 MESSAGE",
  "action": "与请求一致，异常时可能为 ERROR",
  "request_id": "与请求一致，解析失败时可能为空字符串",
  "code": 0,
  "data": {
    "ok": true,
    "message": "request accepted"
  }
}
```

当前实现中：
- 请求成功：`code = 0`，`data.ok = true`，并附带 `data.echo`（回显请求 data；`AUTH` 类请求会自动脱敏 `password/token/refresh_token`）
- `AUTH/REGISTER` 成功时，额外返回 `data.user`，结构如下：
```json
{
  "user_id": "string",
  "numeric_id": "string，纯数字唯一标识，从10000开始递增",
  "user_uuid": "string",
  "username": "string",
  "email": "string",
  "phone": "string",
  "nickname": "string",
  "avatar_url": "string",
  "bio": "string",
  "status": 1,
  "created_at": "UTC ISO8601"
}
```
- `AUTH/REGISTER` 会真实写入数据库表：`user_data` 与 `user_im_profile`
- `AUTH/REGISTER` 成功响应中的 `data.user.numeric_id` 为纯数字唯一标识（从 `10000` 开始，按注册顺序递增）
- `PROFILE/GET` 会按 `data.numeric_id` 联查 `user_data + user_im_profile`，返回 `data.profile`
- `PROFILE/GET` 会对查询结果中的 `user_id` 做一致性校验（需与 `numeric_id` 映射匹配）
- `PROFILE/GET_INFO` 会从 `user_im_profile` 读取资料（含 `extra.signature/extra.theme`）
- `PROFILE/SET_INFO` 会更新 `user_im_profile.nickname/avatar_url/extra.signature/extra.theme`
- `PROFILE/ADD_FRIEND` 接收 `user_numeric_id/friend_numeric_id`，服务端先映射 `user_id` 再写入 `friendships` 双向关系（`status=1`）
- `PROFILE/DELETE_FRIEND` 会删除 `friendships` 双向关系（幂等）
- `PROFILE/LIST_FRIENDS` 会按 `data.numeric_id` 返回该用户的好友列表 `data.friends`
- 请求失败：`code != 0`，`data.ok = false`，`data.message` 给出原因，可能附带 `data.received_payload`

说明：服务端将 `password` 转为 `password_hash` 后再入库，当前实现为 `PBKDF2-HMAC-SHA256`（随机盐 + 高迭代），满足生产可用的基础密码存储要求。

### 4.1 注册接口对应的数据表

- `user_data`：写入 `username/email/phone/password_hash/status/created_at/updated_at`，并生成 `numeric_id`
- `user_im_profile`：写入 `user_id/user_uuid/nickname/avatar_url/bio/is_online/...`

### 4.2 服务器数据库连接配置（环境变量）

服务端 `AUTH/REGISTER` 通过本机 `mysql` 客户端执行事务写入，配置项如下：

- `QT_SERVER_MYSQL_HOST`（必填）
- `QT_SERVER_MYSQL_PORT`（必填）
- `QT_SERVER_MYSQL_DB`（必填）
- `QT_SERVER_MYSQL_USER`（必填）
- `QT_SERVER_MYSQL_PASSWORD`（必填）

## 5. 状态码（第一版）

### 5.1 通用

- `0`：OK
- `1001`：INVALID_REQUEST
- `1002`：INVALID_ACTION
- `1003`：INVALID_PARAM
- `1004`：UNSUPPORTED_TYPE
- `1005`：REQUEST_ID_MISSING
- `1099`：INTERNAL_ERROR

### 5.2 AUTH

- `2001`：AUTH_REQUIRED
- `2002`：TOKEN_INVALID
- `2003`：TOKEN_EXPIRED
- `2004`：LOGIN_FAILED
- `2005`：PERMISSION_DENIED
- `2006`：REGISTER_CONFLICT
- `2007`：REGISTER_FAILED

### 5.3 PROFILE

- `3001`：PROFILE_NOT_FOUND
- `3002`：PROFILE_UPDATE_CONFLICT
- `3003`：PROFILE_VALIDATION_FAILED

### 5.4 MESSAGE

- `4001`：MESSAGE_INVALID
- `4002`：MESSAGE_TOO_LARGE
- `4003`：MESSAGE_TARGET_OFFLINE
- `4004`：MESSAGE_RATE_LIMITED
- `4005`：MESSAGE_NOT_FOUND

## 6. 服务端校验行为

服务端已在 `src/server/websocket_session.cpp` 中强制校验：
- 必须为文本帧（不支持二进制帧）
- 必须是 JSON 对象
- 必须包含并正确类型化 `type/action/request_id/data`
- `type` 必须是 `AUTH/PROFILE/MESSAGE`
- `action` 必须与 `type` 匹配
- `data` 必须满足本文件第 3 节定义的字段约束

任一校验失败都会返回统一错误响应，不会断开连接。
