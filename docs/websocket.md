# WebSocket 改造说明（commit: 71af329a6ab60478311f428734b2ea5554756a06）

## 1. 改造目标

本次提交将服务端连接处理从原有 `session`（TCP echo）切换为 `websocket_session`（WebSocket echo），实现基于 Boost.Beast 的异步 WebSocket 握手、收包、回包流程。

## 2. 变更文件

- `CMakeLists.txt`
- `src/server/echo_server.cpp`
- `src/server/session.cpp`
- `src/server/websocket_session.cpp`（新增）
- `src/server/websocket_session.hpp`（新增）

## 3. 核心改动说明

### 3.1 构建系统

在 `CMakeLists.txt` 中新增了 `src/server/websocket_session.cpp`，确保新会话类参与编译链接。

### 3.2 接入点切换

`src/server/echo_server.cpp` 中的连接处理从：

- `std::make_shared<session>(std::move(socket))->start();`

切换为：

- `std::make_shared<websocket_session>(std::move(socket))->run();`

同时头文件由 `session.hpp` 改为 `websocket_session.hpp`。

这意味着服务端在 `accept` 后不再走纯 TCP echo 流程，而是进入 WebSocket 会话生命周期。

### 3.3 新增 `websocket_session`

`websocket_session` 采用 `std::enable_shared_from_this` + 异步回调链，包含以下阶段：

1. `run()`
- 设置服务端推荐超时参数：`websocket::stream_base::timeout::suggested(...)`
- 设置握手响应 `Server` 头
- 发起异步握手：`async_accept(...)`

2. `on_accept(...)`
- 握手成功后进入读流程 `do_read()`
- 记录并打印连接客户端地址

3. `do_read()` / `on_read(...)`
- 异步读取 WebSocket 帧到 `beast::flat_buffer`
- 打印接收日志
- 保持文本/二进制类型：`ws_.text(ws_.got_text())`
- 将收到的原始负载原样回写（echo）

4. `on_write(...)`
- 发送完成后清空 buffer：`buffer_.consume(buffer_.size())`
- 继续下一轮读取，形成循环

5. 析构
- 会话结束时打印关闭日志

### 3.4 原 `session.cpp` 的变化

`session.cpp` 仅增加了更详细的日志输出（收到字节数、回写提示），功能仍是 TCP echo。  
注意：当前 `echo_server` 已切到 `websocket_session`，因此运行路径主要是 WebSocket，会话类 `session` 目前不再是主路径。

## 4. 当前行为特性

- 服务端支持 WebSocket 握手。
- 收到客户端消息后，按原内容直接回显。
- 支持持续收发（写完继续读）。
- 连接/消息/关闭都有控制台日志，便于联调。

## 5. 与 JSON 协议的关系

本提交实现的是 **WebSocket 传输层改造 + echo 回显**，尚未在服务端内置 JSON 业务协议解析与路由。  
即目前消息体按原始字符串/二进制透传回写，不会解析诸如：

```json
{
  "type": "AUTH | PROFILE | MESSAGE",
  "action": "具体动作",
  "request_id": "uuid",
  "data": {}
}
```

如果后续要落地该 JSON 协议，建议在 `websocket_session::on_read(...)` 中增加：

- JSON 解析与字段校验（`type/action/request_id/data`）
- 按 `type + action` 分发到业务处理器
- 统一响应格式（含 `request_id` 以便客户端关联）
- 错误码与异常响应规范

## 6. 验证建议

可用任意 WebSocket 客户端（浏览器、`wscat`、Qt 客户端）验证：

1. 建立连接能成功握手。
2. 发送文本消息后，服务端原样回显。
3. 连续多次发送，服务端持续响应且无阻塞。
4. 断开连接后服务端打印关闭日志。
