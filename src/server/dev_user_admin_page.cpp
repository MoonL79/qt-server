#include "dev_user_admin_page.hpp"

#include <string>

namespace qt_server {
namespace server {

std::string build_dev_admin_login_page()
{
    return R"PAGE(<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>管理员登录</title>
  <style>
    :root {
      --bg: #f3eee6;
      --text: #2f241d;
      --muted: #6d5b4f;
      --line: rgba(94, 76, 60, 0.14);
      --panel: rgba(255, 252, 246, 0.94);
      --primary: #b3532f;
      --secondary: #1f6c63;
      --danger: #a33f32;
      --shadow: 0 18px 40px rgba(90, 67, 48, 0.14);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background:
        radial-gradient(circle at top left, rgba(179, 83, 47, 0.16), transparent 30%),
        radial-gradient(circle at 85% 10%, rgba(31, 108, 99, 0.15), transparent 24%),
        linear-gradient(180deg, var(--bg) 0%, #fbf7f2 100%);
      color: var(--text);
      font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
      padding: 18px;
    }

    .card {
      width: min(420px, 100%);
      background: var(--panel);
      border: 1px solid rgba(255, 255, 255, 0.56);
      border-radius: 28px;
      box-shadow: var(--shadow);
      padding: 24px;
      display: grid;
      gap: 14px;
    }

    .card h2 {
      margin: 0;
      font-size: 22px;
      letter-spacing: -0.03em;
    }

    #loginForm {
      display: grid;
      gap: 12px;
    }

    label {
      display: grid;
      gap: 8px;
      color: var(--muted);
      font-size: 13px;
      font-weight: 600;
    }

    input,
    button {
      font: inherit;
    }

    input {
      width: 100%;
      padding: 12px 14px;
      border-radius: 14px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.85);
      color: var(--text);
    }

    input:focus {
      outline: none;
      border-color: rgba(179, 83, 47, 0.5);
      box-shadow: 0 0 0 4px rgba(179, 83, 47, 0.12);
    }

    button {
      appearance: none;
      border: 0;
      border-radius: 999px;
      padding: 12px 16px;
      color: #fff;
      background: linear-gradient(135deg, #ca6943, var(--primary));
      cursor: pointer;
    }

    #loginForm button {
      margin-top: 6px;
    }

    .flash {
      display: none;
      padding: 12px 14px;
      border-radius: 14px;
      font-size: 13px;
      line-height: 1.65;
    }

    .flash.error {
      display: block;
      color: var(--danger);
      background: rgba(163, 63, 50, 0.12);
    }

    .flash.info {
      display: block;
      color: var(--secondary);
      background: rgba(31, 108, 99, 0.12);
    }

    @media (max-width: 520px) {
      .card {
        border-radius: 22px;
        padding: 20px;
      }
    }
  </style>
</head>
<body>
  <section class="card">
    <h2>管理员登录</h2>
    <div id="flash" class="flash"></div>
    <form id="loginForm">
      <label>
        用户名
        <input name="username" type="text" autocomplete="username" required maxlength="64" placeholder="管理员用户名">
      </label>
      <label>
        密码
        <input name="password" type="password" autocomplete="current-password" required maxlength="64" placeholder="管理员密码">
      </label>
      <button type="submit">登录</button>
    </form>
  </section>

  <script>
    (function () {
      const flashEl = document.getElementById("flash");

      function setFlash(message, type) {
        flashEl.textContent = message || "";
        flashEl.className = "flash " + (type || "error");
      }

      async function request(path, options) {
        const response = await fetch(path, Object.assign({ credentials: "same-origin" }, options || {}));
        const text = await response.text();
        let payload = {};
        if (text) {
          try {
            payload = JSON.parse(text);
          } catch (error) {
            throw new Error("服务端返回了非 JSON 响应");
          }
        }
        if (!response.ok || payload.ok === false) {
          throw new Error(payload.message || ("请求失败: HTTP " + response.status));
        }
        return payload;
      }

      request("/admin/api/session/me")
        .then(function () {
          window.location.replace("/admin/users");
        })
        .catch(function () {
        });

      document.getElementById("loginForm").addEventListener("submit", function (event) {
        event.preventDefault();
        const formData = new FormData(event.currentTarget);
        request("/admin/api/session/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            username: String(formData.get("username") || ""),
            password: String(formData.get("password") || "")
          })
        }).then(function () {
          setFlash("登录成功，正在进入后台。", "info");
          window.location.replace("/admin/users");
        }).catch(function (error) {
          setFlash(error.message, "error");
        });
      });
    }());
  </script>
</body>
</html>
)PAGE";
}

std::string build_dev_user_admin_page()
{
    return R"PAGE(<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>开发者用户管理后台</title>
  <style>
    :root {
      --bg: #f4efe8;
      --panel: rgba(255, 252, 246, 0.94);
      --line: rgba(94, 76, 60, 0.16);
      --text: #2f241d;
      --muted: #6d5b4f;
      --primary: #b3532f;
      --secondary: #1f6c63;
      --danger: #a33f32;
      --shadow: 0 18px 40px rgba(90, 67, 48, 0.14);
      --radius: 18px;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(179, 83, 47, 0.16), transparent 34%),
        radial-gradient(circle at 85% 15%, rgba(31, 108, 99, 0.15), transparent 28%),
        linear-gradient(180deg, var(--bg) 0%, #fbf7f2 100%);
      font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    }

    .page {
      width: min(1440px, calc(100vw - 32px));
      margin: 24px auto 40px;
    }

    .hero {
      display: grid;
      gap: 14px;
      justify-items: center;
      padding: 28px;
      border: 1px solid rgba(255, 255, 255, 0.48);
      border-radius: 28px;
      background:
        linear-gradient(135deg, rgba(255, 247, 239, 0.95), rgba(246, 255, 251, 0.92)),
        var(--panel);
      box-shadow: var(--shadow);
      backdrop-filter: blur(14px);
    }

    .hero h1 {
      margin: 0;
      font-size: clamp(28px, 4vw, 42px);
      line-height: 1.06;
      letter-spacing: -0.04em;
    }

    .hero p {
      margin: 0;
      color: var(--muted);
      font-size: 15px;
      line-height: 1.7;
      max-width: 900px;
    }

    .hero-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
      justify-content: center;
      margin-top: 6px;
    }

    .pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 9px 14px;
      border-radius: 999px;
      font-size: 13px;
      color: var(--text);
      background: rgba(255, 255, 255, 0.72);
      border: 1px solid rgba(94, 76, 60, 0.11);
    }

    .hero-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      justify-content: center;
      margin-top: 4px;
    }

    .layout {
      display: grid;
      grid-template-columns: minmax(0, 1.45fr) minmax(320px, 0.9fr);
      gap: 18px;
      margin-top: 20px;
    }

    .stack {
      display: grid;
      gap: 18px;
    }

    .panel {
      border-radius: var(--radius);
      background: var(--panel);
      border: 1px solid rgba(255, 255, 255, 0.58);
      box-shadow: var(--shadow);
      overflow: hidden;
    }

    .panel-head {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      padding: 22px 22px 0;
    }

    .panel-head h2 {
      margin: 0;
      font-size: 20px;
      letter-spacing: -0.03em;
    }

    .panel-head p {
      margin: 6px 0 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.6;
    }

    .panel-body {
      padding: 22px;
    }

    .toolbar {
      display: grid;
      grid-template-columns: minmax(0, 1.2fr) minmax(110px, 140px) auto auto;
      gap: 10px;
      align-items: center;
    }

    .toolbar-inline,
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }

    .grid-2,
    .grid-1 {
      display: grid;
      gap: 12px;
    }

    .grid-2 {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }

    label {
      display: grid;
      gap: 7px;
      color: var(--muted);
      font-size: 13px;
      font-weight: 600;
    }

    input,
    textarea,
    select,
    button {
      font: inherit;
    }

    input,
    textarea,
    select {
      width: 100%;
      padding: 12px 14px;
      border-radius: 14px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.84);
      color: var(--text);
    }

    input:focus,
    textarea:focus,
    select:focus {
      outline: none;
      border-color: rgba(179, 83, 47, 0.5);
      box-shadow: 0 0 0 4px rgba(179, 83, 47, 0.12);
    }

    textarea {
      min-height: 110px;
      resize: vertical;
    }

    button {
      appearance: none;
      border: 0;
      border-radius: 999px;
      padding: 12px 16px;
      cursor: pointer;
    }

    button:disabled {
      opacity: 0.56;
      cursor: not-allowed;
    }

    .primary-btn {
      color: #fff;
      background: linear-gradient(135deg, #ca6943, var(--primary));
    }

    .secondary-btn {
      color: var(--secondary);
      background: rgba(31, 108, 99, 0.12);
    }

    .ghost-btn {
      color: var(--text);
      background: rgba(255, 255, 255, 0.72);
      border: 1px solid var(--line);
    }

    .danger-btn {
      color: var(--danger);
      background: rgba(163, 63, 50, 0.12);
    }

    .flash {
      margin-bottom: 14px;
      padding: 12px 14px;
      border-radius: 14px;
      font-size: 13px;
      line-height: 1.6;
      display: none;
    }

    .flash.info {
      display: block;
      color: var(--secondary);
      background: rgba(31, 108, 99, 0.12);
    }

    .flash.error {
      display: block;
      color: var(--danger);
      background: rgba(163, 63, 50, 0.12);
    }

    .summary {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 10px;
    }

    .summary-card {
      min-width: 120px;
      padding: 14px 16px;
      border-radius: 16px;
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.84), rgba(244, 239, 232, 0.72));
      border: 1px solid rgba(94, 76, 60, 0.1);
    }

    .summary-card strong {
      display: block;
      font-size: 22px;
      letter-spacing: -0.04em;
    }

    .summary-card span,
    .muted {
      color: var(--muted);
      font-size: 12px;
      line-height: 1.55;
    }

    .table-wrap {
      margin-top: 16px;
      border-radius: 16px;
      border: 1px solid rgba(94, 76, 60, 0.1);
      overflow: auto;
      background: rgba(255, 255, 255, 0.75);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 930px;
    }

    thead th {
      position: sticky;
      top: 0;
      z-index: 1;
      text-align: left;
      font-size: 12px;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--muted);
      background: rgba(244, 239, 232, 0.96);
      border-bottom: 1px solid rgba(94, 76, 60, 0.12);
      padding: 14px 16px;
      white-space: nowrap;
    }

    tbody td {
      padding: 14px 16px;
      border-bottom: 1px solid rgba(94, 76, 60, 0.08);
      font-size: 13px;
      vertical-align: top;
    }

    tbody tr {
      cursor: pointer;
    }

    tbody tr.selected {
      background: rgba(215, 236, 232, 0.64);
    }

    .user-main {
      display: grid;
      gap: 4px;
    }

    .user-main strong {
      font-size: 14px;
    }

    .tag {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
    }

    .tag.online { color: var(--secondary); background: rgba(31, 108, 99, 0.12); }
    .tag.offline { color: var(--muted); background: rgba(109, 91, 79, 0.1); }
    .tag.enabled { color: var(--secondary); background: rgba(31, 108, 99, 0.12); }
    .tag.disabled { color: var(--danger); background: rgba(163, 63, 50, 0.12); }

    .selected-card {
      border-radius: 16px;
      border: 1px dashed rgba(94, 76, 60, 0.18);
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.68), rgba(249, 244, 238, 0.92));
      padding: 16px;
      margin-bottom: 14px;
      min-height: 112px;
    }

    .selected-card h3 {
      margin: 0 0 8px;
      font-size: 18px;
      letter-spacing: -0.03em;
    }

    .selected-card p {
      margin: 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.7;
    }

    @media (max-width: 1100px) {
      .layout { grid-template-columns: 1fr; }
    }

    @media (max-width: 760px) {
      .page { width: min(100vw - 20px, 100%); margin: 10px auto 28px; }
      .hero, .panel-body, .panel-head { padding-left: 16px; padding-right: 16px; }
      .toolbar, .grid-2 { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="page">
    <section class="hero">
      <h1>开发者用户管理后台</h1>
      <div class="hero-bar">
        <span class="pill" id="adminBadge">当前管理员: 加载中</span>
      </div>
      <div class="hero-actions">
        <button id="refreshBtn" type="button" class="primary-btn">刷新列表</button>
        <button id="logoutBtn" type="button" class="ghost-btn">退出登录</button>
      </div>
    </section>

    <div class="layout">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>用户列表</h2>
            <p>支持按 `user_id`、`numeric_id`、用户名、邮箱、昵称搜索。点击行后可在右侧编辑。</p>
          </div>
        </div>
        <div class="panel-body">
          <div id="flash" class="flash"></div>
          <form id="searchForm" class="grid-1">
            <div class="toolbar">
              <label>
                搜索用户
                <input id="keywordInput" type="text" placeholder="输入 user_id / numeric_id / username / email / nickname">
              </label>
              <label>
                返回条数
                <select id="limitInput">
                  <option value="50">50</option>
                  <option value="100" selected>100</option>
                  <option value="200">200</option>
                </select>
              </label>
              <label class="toolbar-inline">
                <input id="includeDisabledInput" type="checkbox" checked>
                包含已禁用
              </label>
              <button type="submit" class="primary-btn">查询</button>
            </div>
          </form>

          <div class="summary">
            <div class="summary-card">
              <strong id="countAll">0</strong>
              <span>当前结果</span>
            </div>
            <div class="summary-card">
              <strong id="countEnabled">0</strong>
              <span>启用账号</span>
            </div>
            <div class="summary-card">
              <strong id="countOnline">0</strong>
              <span>在线账号</span>
            </div>
          </div>

          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>账号</th>
                  <th>昵称 / 邮箱</th>
                  <th>状态</th>
                  <th>在线</th>
                  <th>最后登录</th>
                  <th>创建时间</th>
                </tr>
              </thead>
              <tbody id="usersBody">
                <tr><td colspan="6" class="muted">正在等待首次加载。</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <div class="stack">
        <section class="panel">
          <div class="panel-head">
            <div>
              <h2>创建用户</h2>
              <p>创建普通 IM 用户，不会影响管理员账号体系。</p>
            </div>
          </div>
          <div class="panel-body">
            <form id="createForm" class="grid-1">
              <div class="grid-2">
                <label>
                  用户名
                  <input name="username" type="text" required maxlength="32" placeholder="例如 dev_user_01">
                </label>
                <label>
                  昵称
                  <input name="nickname" type="text" required maxlength="64" placeholder="显示给客户端的昵称">
                </label>
              </div>
              <div class="grid-2">
                <label>
                  邮箱
                  <input name="email" type="email" required maxlength="128" placeholder="name@example.com">
                </label>
                <label>
                  手机号
                  <input name="phone" type="text" maxlength="32" placeholder="可选">
                </label>
              </div>
              <div class="grid-2">
                <label>
                  初始密码
                  <input name="password" type="password" required minlength="8" maxlength="64" placeholder="必须包含大小写字母和数字">
                </label>
                <label>
                  账号状态
                  <select name="status">
                    <option value="1" selected>启用</option>
                    <option value="0">禁用</option>
                  </select>
                </label>
              </div>
              <label>
                头像 URL
                <input name="avatar_url" type="text" maxlength="255" placeholder="可选">
              </label>
              <label>
                简介
                <textarea name="bio" maxlength="255" placeholder="可选"></textarea>
              </label>
              <div class="actions">
                <button type="submit" class="primary-btn">创建用户</button>
                <button type="reset" class="ghost-btn">清空表单</button>
              </div>
            </form>
          </div>
        </section>

        <section class="panel">
          <div class="panel-head">
            <div>
              <h2>编辑选中用户</h2>
              <p>这里不开放删除，避免误删聊天和文件关联数据。</p>
            </div>
          </div>
          <div class="panel-body">
            <div id="selectedCard" class="selected-card">
              <h3>未选择用户</h3>
              <p>从左侧列表点击一行后，这里会显示当前用户概览，并允许修改资料或重置密码。</p>
            </div>

            <form id="editForm" class="grid-1">
              <div class="grid-2">
                <label>
                  邮箱
                  <input id="editEmail" type="email" required maxlength="128">
                </label>
                <label>
                  手机号
                  <input id="editPhone" type="text" maxlength="32">
                </label>
              </div>
              <div class="grid-2">
                <label>
                  昵称
                  <input id="editNickname" type="text" required maxlength="64">
                </label>
                <label>
                  账号状态
                  <select id="editStatus">
                    <option value="1">启用</option>
                    <option value="0">禁用</option>
                  </select>
                </label>
              </div>
              <label>
                头像 URL
                <input id="editAvatarUrl" type="text" maxlength="255">
              </label>
              <label>
                简介
                <textarea id="editBio" maxlength="255"></textarea>
              </label>
              <div class="actions">
                <button id="saveUserBtn" type="submit" class="secondary-btn" disabled>保存修改</button>
              </div>
            </form>

            <hr style="border:0;border-top:1px solid rgba(94,76,60,0.1);margin:18px 0;">

            <form id="resetPasswordForm" class="grid-1">
              <label>
                新密码
                <input id="resetPasswordInput" type="password" required minlength="8" maxlength="64" placeholder="必须包含大小写字母和数字">
              </label>
              <div class="actions">
                <button id="resetPasswordBtn" type="submit" class="danger-btn" disabled>重置密码</button>
              </div>
            </form>
          </div>
        </section>
      </div>
    </div>
  </div>

  <script>
    (function () {
      const state = {
        admin: null,
        users: [],
        selectedUserId: null
      };

      const flashEl = document.getElementById("flash");
      const usersBody = document.getElementById("usersBody");
      const countAll = document.getElementById("countAll");
      const countEnabled = document.getElementById("countEnabled");
      const countOnline = document.getElementById("countOnline");
      const saveUserBtn = document.getElementById("saveUserBtn");
      const resetPasswordBtn = document.getElementById("resetPasswordBtn");

      function escapeHtml(value) {
        return String(value == null ? "" : value)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#39;");
      }

      function setFlash(message, type) {
        flashEl.textContent = message || "";
        flashEl.className = "flash " + (type || "info");
      }

      async function api(path, options) {
        const response = await fetch(path, Object.assign({ credentials: "same-origin" }, options || {}));
        const text = await response.text();
        let payload = {};
        if (text) {
          try {
            payload = JSON.parse(text);
          } catch (error) {
            throw new Error("服务端返回了非 JSON 响应");
          }
        }
        if (response.status === 401) {
          window.location.replace("/admin/login");
          throw new Error(payload.message || "管理员会话已失效");
        }
        if (!response.ok || payload.ok === false) {
          throw new Error(payload.message || ("请求失败: HTTP " + response.status));
        }
        return payload;
      }

      function renderAdminBadge() {
        const badge = document.getElementById("adminBadge");
        if (!state.admin) {
          badge.innerHTML = "当前管理员: 未登录";
          return;
        }
        const displayName = state.admin.display_name || state.admin.username;
        badge.innerHTML = "当前管理员: <strong>" + escapeHtml(displayName) + "</strong>";
      }

      function updateSummary() {
        countAll.textContent = String(state.users.length);
        countEnabled.textContent = String(state.users.filter(function (user) {
          return Number(user.status) === 1;
        }).length);
        countOnline.textContent = String(state.users.filter(function (user) {
          return Boolean(user.is_online);
        }).length);
      }

      function renderSelectedCard(user) {
        const card = document.getElementById("selectedCard");
        if (!user) {
          card.innerHTML = "<h3>未选择用户</h3><p>从左侧列表点击一行后，这里会显示当前用户概览，并允许修改资料或重置密码。</p>";
          return;
        }
        const statusLabel = Number(user.status) === 1 ? "启用" : "禁用";
        const onlineLabel = user.is_online ? "在线" : "离线";
        card.innerHTML =
          "<h3>" + escapeHtml(user.nickname || user.username) + "</h3>" +
          "<p>" +
          "user_id: <strong>" + escapeHtml(user.user_id) + "</strong> / " +
          "numeric_id: <strong>" + escapeHtml(user.numeric_id) + "</strong><br>" +
          "username: <strong>" + escapeHtml(user.username) + "</strong><br>" +
          "email: <strong>" + escapeHtml(user.email || "-") + "</strong><br>" +
          "状态: <strong>" + escapeHtml(statusLabel) + "</strong>，在线: <strong>" + escapeHtml(onlineLabel) + "</strong><br>" +
          "最后登录: <strong>" + escapeHtml(user.last_login_at || "-") + "</strong>" +
          "</p>";
      }

      function applySelection(user) {
        state.selectedUserId = user ? String(user.user_id) : null;
        renderSelectedCard(user);
        document.getElementById("editEmail").value = user ? (user.email || "") : "";
        document.getElementById("editPhone").value = user ? (user.phone || "") : "";
        document.getElementById("editNickname").value = user ? (user.nickname || "") : "";
        document.getElementById("editStatus").value = user ? String(user.status) : "1";
        document.getElementById("editAvatarUrl").value = user ? (user.avatar_url || "") : "";
        document.getElementById("editBio").value = user ? (user.bio || "") : "";
        document.getElementById("resetPasswordInput").value = "";
        saveUserBtn.disabled = !user;
        resetPasswordBtn.disabled = !user;
      }

      function findSelectedUser() {
        return state.users.find(function (user) {
          return String(user.user_id) === String(state.selectedUserId);
        }) || null;
      }

      function renderUsers() {
        if (!state.users.length) {
          usersBody.innerHTML = "<tr><td colspan='6' class='muted'>没有匹配的用户记录。</td></tr>";
          applySelection(null);
          updateSummary();
          return;
        }

        usersBody.innerHTML = state.users.map(function (user) {
          const selected = String(user.user_id) === String(state.selectedUserId);
          const statusClass = Number(user.status) === 1 ? "enabled" : "disabled";
          const statusLabel = Number(user.status) === 1 ? "启用" : "禁用";
          const onlineClass = user.is_online ? "online" : "offline";
          const onlineLabel = user.is_online ? "在线" : "离线";
          return (
            "<tr class='" + (selected ? "selected" : "") + "' data-user-id='" + escapeHtml(user.user_id) + "'>" +
              "<td><div class='user-main'><strong>" + escapeHtml(user.username) + "</strong><span class='muted'>ID " + escapeHtml(user.user_id) + " / #" + escapeHtml(user.numeric_id) + "</span></div></td>" +
              "<td><div class='user-main'><strong>" + escapeHtml(user.nickname || "-") + "</strong><span class='muted'>" + escapeHtml(user.email || "-") + "</span></div></td>" +
              "<td><span class='tag " + statusClass + "'>" + escapeHtml(statusLabel) + "</span></td>" +
              "<td><span class='tag " + onlineClass + "'>" + escapeHtml(onlineLabel) + "</span></td>" +
              "<td>" + escapeHtml(user.last_login_at || "-") + "</td>" +
              "<td>" + escapeHtml(user.created_at || "-") + "</td>" +
            "</tr>"
          );
        }).join("");

        Array.prototype.forEach.call(usersBody.querySelectorAll("tr[data-user-id]"), function (row) {
          row.addEventListener("click", function () {
            const userId = row.getAttribute("data-user-id");
            const user = state.users.find(function (item) {
              return String(item.user_id) === String(userId);
            }) || null;
            applySelection(user);
            renderUsers();
          });
        });

        const selectedUser = findSelectedUser() || state.users[0];
        applySelection(selectedUser);
        updateSummary();
      }

      async function loadUsers() {
        const params = new URLSearchParams();
        const keyword = document.getElementById("keywordInput").value.trim();
        if (keyword) {
          params.set("keyword", keyword);
        }
        params.set("limit", document.getElementById("limitInput").value);
        params.set("include_disabled", document.getElementById("includeDisabledInput").checked ? "1" : "0");
        const payload = await api("/admin/api/users?" + params.toString());
        state.users = Array.isArray(payload.users) ? payload.users : [];
        if (!state.users.some(function (user) { return String(user.user_id) === String(state.selectedUserId); })) {
          state.selectedUserId = state.users.length ? String(state.users[0].user_id) : null;
        }
        renderUsers();
        setFlash("用户列表已刷新。", "info");
      }

      async function loadSession() {
        const payload = await api("/admin/api/session/me");
        state.admin = payload.admin || null;
        renderAdminBadge();
      }

      document.getElementById("refreshBtn").addEventListener("click", function () {
        loadUsers().catch(function (error) {
          setFlash(error.message, "error");
        });
      });

      document.getElementById("logoutBtn").addEventListener("click", function () {
        api("/admin/api/session/logout", { method: "POST" })
          .then(function () {
            window.location.replace("/admin/login");
          })
          .catch(function () {
            window.location.replace("/admin/login");
          });
      });

      document.getElementById("searchForm").addEventListener("submit", function (event) {
        event.preventDefault();
        loadUsers().catch(function (error) {
          setFlash(error.message, "error");
        });
      });

      document.getElementById("createForm").addEventListener("submit", function (event) {
        event.preventDefault();
        const form = event.currentTarget;
        const formData = new FormData(form);
        api("/admin/api/users", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            username: String(formData.get("username") || ""),
            nickname: String(formData.get("nickname") || ""),
            email: String(formData.get("email") || ""),
            phone: String(formData.get("phone") || ""),
            password: String(formData.get("password") || ""),
            status: Number(formData.get("status") || 1),
            avatar_url: String(formData.get("avatar_url") || ""),
            bio: String(formData.get("bio") || "")
          })
        }).then(function (response) {
          form.reset();
          state.selectedUserId = response.user ? String(response.user.user_id) : null;
          return loadUsers().then(function () {
            setFlash("用户创建成功。", "info");
          });
        }).catch(function (error) {
          setFlash(error.message, "error");
        });
      });

      document.getElementById("editForm").addEventListener("submit", function (event) {
        event.preventDefault();
        const user = findSelectedUser();
        if (!user) {
          setFlash("请先选择一个用户。", "error");
          return;
        }
        api("/admin/api/users/" + encodeURIComponent(String(user.user_id)), {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: document.getElementById("editEmail").value,
            phone: document.getElementById("editPhone").value,
            nickname: document.getElementById("editNickname").value,
            status: Number(document.getElementById("editStatus").value),
            avatar_url: document.getElementById("editAvatarUrl").value,
            bio: document.getElementById("editBio").value
          })
        }).then(function () {
          return loadUsers().then(function () {
            state.selectedUserId = String(user.user_id);
            renderUsers();
            setFlash("用户资料已更新。", "info");
          });
        }).catch(function (error) {
          setFlash(error.message, "error");
        });
      });

      document.getElementById("resetPasswordForm").addEventListener("submit", function (event) {
        event.preventDefault();
        const user = findSelectedUser();
        if (!user) {
          setFlash("请先选择一个用户。", "error");
          return;
        }
        api("/admin/api/users/" + encodeURIComponent(String(user.user_id)) + "/reset-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: document.getElementById("resetPasswordInput").value })
        }).then(function () {
          document.getElementById("resetPasswordInput").value = "";
          setFlash("密码已重置。", "info");
        }).catch(function (error) {
          setFlash(error.message, "error");
        });
      });

      loadSession()
        .then(loadUsers)
        .catch(function (error) {
          setFlash(error.message, "error");
        });
    }());
  </script>
</body>
</html>
)PAGE";
}

} // namespace server
} // namespace qt_server
