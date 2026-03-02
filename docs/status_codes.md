# WebSocket 状态码规范（V1）

## 1. 目标

统一 `code` 字段语义，规则如下：

- `code = 0`：请求成功
- `code != 0`：请求失败
- 响应中必须包含 `code`

## 2. 编码清单

### 2.1 通用（1xxx）

- `0`：`OK`
- `1001`：`INVALID_REQUEST`
- `1002`：`INVALID_ACTION`
- `1003`：`INVALID_PARAM`
- `1004`：`UNSUPPORTED_TYPE`
- `1005`：`REQUEST_ID_MISSING`
- `1099`：`INTERNAL_ERROR`

### 2.2 AUTH（2xxx）

- `2001`：`AUTH_REQUIRED`
- `2002`：`TOKEN_INVALID`
- `2003`：`TOKEN_EXPIRED`
- `2004`：`LOGIN_FAILED`
- `2005`：`PERMISSION_DENIED`

### 2.3 PROFILE（3xxx）

- `3001`：`PROFILE_NOT_FOUND`
- `3002`：`PROFILE_UPDATE_CONFLICT`
- `3003`：`PROFILE_VALIDATION_FAILED`

### 2.4 MESSAGE（4xxx）

- `4001`：`MESSAGE_INVALID`
- `4002`：`MESSAGE_TOO_LARGE`
- `4003`：`MESSAGE_TARGET_OFFLINE`
- `4004`：`MESSAGE_RATE_LIMITED`
- `4005`：`MESSAGE_NOT_FOUND`

## 3. 当前服务端实现映射

`src/server/websocket_session.cpp` 当前行为：

- 成功请求：返回 `code = 0`
- 非文本帧：`1001 INVALID_REQUEST`
- 非法 JSON / 信封字段缺失或类型错误：`1001 INVALID_REQUEST`
- `request_id` 缺失或空：`1005 REQUEST_ID_MISSING`
- `type` 非法：`1004 UNSUPPORTED_TYPE`
- `action` 非法或不匹配：`1002 INVALID_ACTION`
- `AUTH` 数据字段校验失败：`1003 INVALID_PARAM`
- `PROFILE` 数据字段校验失败：`3003 PROFILE_VALIDATION_FAILED`
- `MESSAGE` 数据字段校验失败：`4001 MESSAGE_INVALID`

> 注：部分业务码（如 `2004/3001/4003`）已预留，后续接入真实业务逻辑时启用。

## 4. 响应示例

成功：

```json
{
  "type": "AUTH",
  "action": "LOGIN",
  "request_id": "uuid",
  "code": 0,
  "data": {
    "ok": true,
    "message": "login accepted (verification disabled)"
  }
}
```

失败：

```json
{
  "type": "MESSAGE",
  "action": "ERROR",
  "request_id": "",
  "code": 1001,
  "data": {
    "ok": false,
    "message": "invalid JSON payload"
  }
}
```
