# qt-server

毕业设计服务端。

## 如何部署

```shell
git clone git@github.com:MoonL79/qt-server.git
cd qt-server
cmake
# 待完善
```

## 开发者用户管理后台

- 登录页面路由：`/admin/login`
- 后台首页路由：`/admin/overview`
- 管理页面路由：`/admin/users`、`/admin/groups`、`/admin/conversations`、`/admin/sessions`、`/admin/files`
- 会话接口前缀：`/admin/api/session`
- 总览接口：`/admin/api/overview`
- 用户接口前缀：`/admin/api/users`
- 群组接口前缀：`/admin/api/groups`
- 会话与消息接口前缀：`/admin/api/conversations`
- 在线状态接口：`/admin/api/sessions`
- 文件接口前缀：`/admin/api/files`
- 后台专用聊天文件下载：`/admin/api/files/chat/{file_id}/download`
- 鉴权方式：独立 `admin_users` + HTTP cookie session
- session cookie 作用域：`/admin`
- 首次访问且 `admin_users` 为空时，会自动创建引导管理员
- 默认引导账号：`admin / Admin123456`
- 可通过环境变量覆盖：
  `QT_SERVER_ADMIN_BOOTSTRAP_USERNAME`
  `QT_SERVER_ADMIN_BOOTSTRAP_PASSWORD`
  `QT_SERVER_ADMIN_BOOTSTRAP_DISPLAY_NAME`
- 这套后台鉴权只作用于 `/admin/*`
- 本轮后台扩展不会改动原有文件传输入口：
  `/upload/avatar`
  `/upload/chat-file`
  `/download/chat-file/*`
