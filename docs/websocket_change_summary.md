# WebSocket 协议改造总结（当前工作区）

## 1. 本次改造范围

当前工作区已完成以下文件改动：

- `CMakeLists.txt`
- `src/server/websocket_session.hpp`
- `src/server/websocket_session.cpp`
- `docs/websocket.md`
- `docs/status_codes.md`

## 2. 统一通信信封

服务端与客户端统一使用以下 JSON 文本帧：

```json
{
  "type": "AUTH | PROFILE | MESSAGE",
  "action": "枚举动作",
  "request_id": "uuid",
  "code": 0,
  "data": {}
}
```

字段约束：
- `type`：必填，`AUTH | PROFILE | MESSAGE`
- `action`：必填，且必须与 `type` 匹配
- `request_id`：必填，字符串，响应中原样回传
- `code`：状态码，响应必填；`0` 表示成功
- `data`：必填，对象，结构由 `type + action` 决定

## 3. Action 枚举与 data 结构

### 3.1 AUTH

- `LOGIN`：`{ "username": "string", "password": "string" }`
- `LOGOUT`：`{ "token": "string" }`
- `REFRESH_TOKEN`：`{ "refresh_token": "string" }`

### 3.2 PROFILE

- `GET`：`{ "user_id": "string" }`
- `GET_INFO`：`{ "user_id": "string" }`，响应 `data.profile` 包含：
  `avatar_url`、`nickname`、`signature`、`theme`（未设置默认 `default`）
- `SET_INFO`：`{ "user_id", "avatar_url", "nickname", "signature", "theme?" }`，
  响应 `data.profile` 返回数据库保存后的个人信息
- `UPDATE`：`{ "user_id": "string", "nickname": "string", "avatar_url": "string" }`

### 3.3 MESSAGE

- `SEND`：`{ "conversation_id": "string", "content": "string" }`
- `PULL`：`{ "conversation_id": "string" }`
- `ACK`：`{ "conversation_id": "string", "message_id": "string", "read": true }`

## 4. 服务端实现行为

`websocket_session` 已从“原样 echo”升级为“协议解析 + 校验 + 统一响应”：

1. 仅支持文本帧；二进制帧会返回错误响应。
2. 解析 JSON 并校验 `type/action/request_id/data` 基础字段。
3. 校验 `type` 枚举、`action` 枚举与 `type-action` 组合合法性。
4. 按 `type + action` 校验 `data` 必填字段和字段类型。
5. 统一返回同信封格式响应：
   - `code = 0 / 非0`
   - `data.ok = true/false`
   - `data.message = 描述信息`
   - 成功时包含 `data.echo`（回显请求 data）

状态码第一版清单与映射说明见：`docs/status_codes.md`。

## 5. 登录校验（当前实现）

服务端已启用 `AUTH + LOGIN` 的真实账号密码校验：

- 从 `user_data` 查询 `password_hash`
- 使用同注册流程一致的 `PBKDF2-HMAC-SHA256` 规则进行密码校验
- 校验失败返回 `2004 LOGIN_FAILED`
- 校验成功返回 `data.user`，并更新 `last_login_at` 与在线状态字段

## 6. 构建依赖调整

`CMakeLists.txt` 已加入 `Boost::json`：

- `find_package(Boost 1.83 REQUIRED COMPONENTS system json)`
- `target_link_libraries(... Boost::json ...)`

用于服务端 JSON 解析与序列化。
