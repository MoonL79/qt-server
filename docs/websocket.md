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
- `LOGOUT`
- `REFRESH_TOKEN`

### 2.2 PROFILE
- `GET`
- `UPDATE`

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

3. `action = REFRESH_TOKEN`
```json
{
  "refresh_token": "string"
}
```

### 3.2 PROFILE 的 data

1. `action = GET`
```json
{
  "user_id": "string"
}
```

2. `action = UPDATE`
```json
{
  "user_id": "string",
  "nickname": "string",
  "avatar_url": "string"
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
  "read": true
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
- 请求成功：`code = 0`，`data.ok = true`，并附带 `data.echo`（回显请求 data）
- 请求失败：`code != 0`，`data.ok = false`，`data.message` 给出原因，可能附带 `data.received_payload`

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
