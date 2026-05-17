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

- 管理页面路由：`/admin/users`
- 管理接口前缀：`/admin/api/users`
- 鉴权方式：请求头 `X-Dev-Admin-Token`
- 默认 token：`dev-admin-123456`
- 可通过环境变量 `QT_SERVER_DEV_ADMIN_TOKEN` 覆盖默认 token
