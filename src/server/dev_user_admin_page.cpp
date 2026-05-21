#include "dev_user_admin_page.hpp"

#include <sstream>
#include <string>

namespace qt_server {
namespace server {

namespace {

enum class admin_page_kind
{
    overview,
    users,
    groups,
    conversations,
    sessions,
    files
};

struct admin_page_meta
{
    admin_page_kind kind;
    const char* path;
    const char* label;
    const char* eyebrow;
    const char* title;
    const char* heading;
    const char* summary;
};

const admin_page_meta& get_admin_page_meta(admin_page_kind kind)
{
    static const admin_page_meta k_overview = {
        admin_page_kind::overview,
        "/admin/overview",
        "总览",
        "Developer Console",
        "后台总览",
        "Web 管理后台",
        "先把入口和信息架构搭起来。本轮改动只落在 /admin/*，不触碰文件上传下载链路。 "
    };
    static const admin_page_meta k_users = {
        admin_page_kind::users,
        "/admin/users",
        "用户",
        "User Workspace",
        "用户管理",
        "用户管理工作台",
        "保留现有用户创建、编辑、重置密码能力，并接入统一后台壳。"
    };
    static const admin_page_meta k_groups = {
        admin_page_kind::groups,
        "/admin/groups",
        "群组",
        "Groups Console",
        "群组管理",
        "群组管理工作台",
        "按群号、群名、群主检索群组，并查看成员与最近消息，只走后台只读接口。"
    };
    static const admin_page_meta k_conversations = {
        admin_page_kind::conversations,
        "/admin/conversations",
        "会话",
        "Message Diagnostics",
        "会话与消息",
        "会话与消息诊断",
        "按用户、群号、会话 ID 检索消息链路，查看时间线和送达回执。"
    };
    static const admin_page_meta k_sessions = {
        admin_page_kind::sessions,
        "/admin/sessions",
        "在线",
        "Presence Monitor",
        "在线状态与连接",
        "在线状态与连接",
        "同时展示用户在线态与 websocket 运行时快照，读取的是旁路管理视图。"
    };
    static const admin_page_meta k_files = {
        admin_page_kind::files,
        "/admin/files",
        "文件",
        "Files Center",
        "文件与头像中心",
        "文件与头像中心",
        "只看头像与聊天文件元数据，后台下载走独立管理路由，不碰原有传输链路。"
    };

    switch (kind) {
    case admin_page_kind::overview:
        return k_overview;
    case admin_page_kind::users:
        return k_users;
    case admin_page_kind::groups:
        return k_groups;
    case admin_page_kind::conversations:
        return k_conversations;
    case admin_page_kind::sessions:
        return k_sessions;
    case admin_page_kind::files:
    default:
        return k_files;
    }
}

void append_admin_nav_link(std::ostringstream& html,
                           admin_page_kind active_kind,
                           admin_page_kind link_kind)
{
    const admin_page_meta& meta = get_admin_page_meta(link_kind);
    html << "<a class='nav-link";
    if (active_kind == link_kind) {
        html << " active";
    }
    html << "' href='" << meta.path << "'>" << meta.label << "</a>";
}

std::string build_admin_shell(admin_page_kind kind,
                              const std::string& body_html,
                              const std::string& page_script)
{
    const admin_page_meta& meta = get_admin_page_meta(kind);

    std::ostringstream html;
    html << R"HTML(<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>)HTML" << meta.title << R"HTML(</title>
  <style>
    :root {
      --bg: #f4efe8;
      --panel: rgba(255, 252, 246, 0.94);
      --panel-strong: rgba(255, 250, 242, 0.98);
      --line: rgba(94, 76, 60, 0.16);
      --line-soft: rgba(94, 76, 60, 0.1);
      --text: #2f241d;
      --muted: #6d5b4f;
      --primary: #b3532f;
      --secondary: #1f6c63;
      --danger: #a33f32;
      --shadow: 0 18px 40px rgba(90, 67, 48, 0.14);
      --radius: 20px;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(179, 83, 47, 0.16), transparent 34%),
        radial-gradient(circle at 85% 12%, rgba(31, 108, 99, 0.14), transparent 24%),
        linear-gradient(180deg, var(--bg) 0%, #fbf7f2 100%);
      font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    }

    a {
      color: inherit;
      text-decoration: none;
    }

    .shell {
      min-height: 100vh;
      display: grid;
      grid-template-columns: 280px minmax(0, 1fr);
    }

    .sidebar {
      min-height: 100vh;
      padding: 26px 20px;
      display: grid;
      align-content: start;
      gap: 24px;
      border-right: 1px solid rgba(255, 255, 255, 0.56);
      background: rgba(255, 248, 240, 0.62);
      backdrop-filter: blur(16px);
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .brand-mark {
      width: 44px;
      height: 44px;
      border-radius: 14px;
      display: grid;
      place-items: center;
      color: #fff;
      font-weight: 800;
      background: linear-gradient(135deg, #ca6943, var(--primary));
      box-shadow: 0 14px 30px rgba(179, 83, 47, 0.24);
    }

    .brand-copy {
      display: grid;
      gap: 4px;
    }

    .brand-copy strong {
      font-size: 16px;
      letter-spacing: -0.03em;
    }

    .brand-copy span {
      color: var(--muted);
      font-size: 12px;
    }

    .nav {
      display: grid;
      gap: 8px;
    }

    .nav-link {
      display: flex;
      align-items: center;
      min-height: 46px;
      padding: 10px 14px;
      border-radius: 16px;
      color: var(--muted);
      border: 1px solid transparent;
      background: rgba(255, 255, 255, 0.48);
      transition: background 0.18s ease, color 0.18s ease, transform 0.18s ease;
    }

    .nav-link:hover {
      color: var(--text);
      background: rgba(255, 255, 255, 0.82);
      transform: translateX(2px);
    }

    .nav-link.active {
      color: #fff;
      background: linear-gradient(135deg, #ca6943, var(--primary));
      box-shadow: 0 16px 34px rgba(179, 83, 47, 0.22);
    }

    .side-note {
      padding: 18px;
      border-radius: 18px;
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.72), rgba(250, 244, 236, 0.86));
      border: 1px solid var(--line-soft);
    }

    .side-note h2,
    .panel-head h2,
    .selected-card h3 {
      margin: 0;
      letter-spacing: -0.03em;
    }

    .side-note p,
    .panel-head p,
    .selected-card p,
    .muted {
      color: var(--muted);
      font-size: 13px;
      line-height: 1.65;
    }

    .main {
      padding: 24px 28px 40px;
      display: grid;
      align-content: start;
      gap: 18px;
    }

    .topbar {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 18px;
    }

    .eyebrow {
      display: inline-flex;
      align-items: center;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 11px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--secondary);
      background: rgba(31, 108, 99, 0.1);
    }

    .topbar h1 {
      margin: 10px 0 8px;
      font-size: clamp(28px, 4vw, 40px);
      line-height: 1.05;
      letter-spacing: -0.05em;
    }

    .topbar p {
      margin: 0;
      max-width: 820px;
      color: var(--muted);
      line-height: 1.75;
      font-size: 14px;
    }

    .top-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      justify-content: flex-end;
    }

    .pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      min-height: 42px;
      padding: 10px 14px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.76);
      border: 1px solid rgba(94, 76, 60, 0.12);
      font-size: 13px;
    }

    button {
      appearance: none;
      border: 0;
      border-radius: 999px;
      padding: 12px 16px;
      cursor: pointer;
      font: inherit;
    }

    button:disabled {
      opacity: 0.56;
      cursor: not-allowed;
    }

    .primary-btn {
      color: #fff;
      background: linear-gradient(135deg, #ca6943, var(--primary));
    }

    .primary-btn,
    .secondary-btn,
    .ghost-btn,
    .danger-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 44px;
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
      display: none;
      padding: 12px 14px;
      border-radius: 16px;
      font-size: 13px;
      line-height: 1.6;
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

    .content {
      display: grid;
      gap: 20px;
    }

    .panel {
      border-radius: 24px;
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
      font-size: 20px;
    }

    .panel-head p {
      margin: 6px 0 0;
    }

    .panel-body {
      padding: 22px;
    }

    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 14px;
    }

    .metric-card {
      padding: 18px;
      border-radius: 18px;
      border: 1px solid var(--line-soft);
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.88), rgba(246, 240, 232, 0.72));
    }

    .metric-card strong {
      display: block;
      margin-top: 8px;
      font-size: 28px;
      letter-spacing: -0.05em;
    }

    .metric-card span {
      color: var(--muted);
      font-size: 12px;
      line-height: 1.6;
    }

    .overview-grid,
    .placeholder-grid {
      display: grid;
      grid-template-columns: minmax(0, 1.1fr) minmax(320px, 0.9fr);
      gap: 20px;
    }

    .recent-users,
    .card-list,
    .stack {
      display: grid;
      gap: 14px;
    }

    .recent-user,
    .placeholder-card,
    .action-card,
    .status-strip {
      padding: 18px;
      border-radius: 18px;
      border: 1px solid var(--line-soft);
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.8), rgba(249, 244, 238, 0.92));
    }

    .recent-user-top,
    .inline-split,
    .actions,
    .toolbar-inline {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }

    .recent-user-top,
    .inline-split {
      justify-content: space-between;
    }

    .actions,
    .toolbar-inline {
      justify-content: flex-start;
    }

    .recent-user strong,
    .placeholder-card strong,
    .action-card strong {
      font-size: 15px;
    }

    .status-strip {
      display: grid;
      gap: 8px;
      background: linear-gradient(135deg, rgba(255, 247, 239, 0.95), rgba(246, 255, 251, 0.92));
    }

    .action-links {
      display: grid;
      gap: 10px;
    }

    .action-link {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      padding: 14px 16px;
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.76);
      border: 1px solid var(--line-soft);
    }

    .action-link span:last-child {
      color: var(--muted);
      font-size: 12px;
    }

    .note-grid {
      display: grid;
      gap: 12px;
    }

    .note-grid p {
      margin: 0;
      padding: 14px 16px;
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.74);
      border: 1px solid var(--line-soft);
      color: var(--muted);
      font-size: 13px;
      line-height: 1.65;
    }

    .users-layout {
      display: grid;
      grid-template-columns: minmax(0, 1.45fr) minmax(320px, 0.95fr);
      gap: 20px;
    }

    .toolbar {
      display: grid;
      grid-template-columns: minmax(0, 1.2fr) minmax(110px, 140px) auto auto;
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
    select {
      width: 100%;
      padding: 12px 14px;
      border-radius: 14px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.84);
      color: var(--text);
      font: inherit;
    }

    input:focus,
    textarea:focus,
    select:focus {
      outline: none;
      border-color: rgba(179, 83, 47, 0.5);
      box-shadow: 0 0 0 4px rgba(179, 83, 47, 0.12);
    }

    input[type="checkbox"] {
      width: auto;
      padding: 0;
      border: 0;
      background: transparent;
      box-shadow: none;
      accent-color: var(--secondary);
    }

    textarea {
      min-height: 110px;
      resize: vertical;
    }

    .summary-row {
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
      border: 1px solid var(--line-soft);
    }

    .summary-card strong {
      display: block;
      font-size: 22px;
      letter-spacing: -0.04em;
    }

    .summary-card span {
      color: var(--muted);
      font-size: 12px;
      line-height: 1.55;
    }

    .table-wrap {
      margin-top: 16px;
      border-radius: 16px;
      border: 1px solid var(--line-soft);
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

    .tag.online,
    .tag.enabled {
      color: var(--secondary);
      background: rgba(31, 108, 99, 0.12);
    }

    .tag.offline {
      color: var(--muted);
      background: rgba(109, 91, 79, 0.1);
    }

    .tag.disabled {
      color: var(--danger);
      background: rgba(163, 63, 50, 0.12);
    }

    .selected-card {
      border-radius: 18px;
      border: 1px dashed rgba(94, 76, 60, 0.18);
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.68), rgba(249, 244, 238, 0.92));
      padding: 16px;
      min-height: 112px;
    }

    .selected-card h3 {
      font-size: 18px;
      margin-bottom: 8px;
    }

    .selected-card p {
      margin: 0;
    }

    .divider {
      border: 0;
      border-top: 1px solid rgba(94, 76, 60, 0.1);
      margin: 18px 0;
    }

    .empty-state {
      padding: 18px;
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.76);
      border: 1px solid var(--line-soft);
      color: var(--muted);
      font-size: 13px;
      line-height: 1.65;
    }

    .mono {
      font-family: "Cascadia Mono", "Consolas", "Courier New", monospace;
      font-size: 12px;
      word-break: break-all;
    }

    .pre-wrap {
      white-space: pre-wrap;
      word-break: break-word;
    }

    .thumb {
      width: 52px;
      height: 52px;
      border-radius: 14px;
      object-fit: cover;
      border: 1px solid var(--line-soft);
      background: rgba(255, 255, 255, 0.9);
    }

    .thumb-fallback {
      width: 52px;
      height: 52px;
      display: grid;
      place-items: center;
      border-radius: 14px;
      border: 1px dashed var(--line-soft);
      background: rgba(255, 255, 255, 0.72);
      color: var(--muted);
      font-size: 11px;
    }

    .inline-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }

    .detail-list {
      display: grid;
      gap: 10px;
    }

    .detail-list p {
      margin: 0;
    }

    .compact-card {
      padding: 14px 16px;
      border-radius: 16px;
      border: 1px solid var(--line-soft);
      background: rgba(255, 255, 255, 0.72);
    }

    .text-link {
      color: var(--primary);
      font-weight: 700;
    }

    .content-snippet {
      max-width: 520px;
      white-space: pre-wrap;
      word-break: break-word;
      line-height: 1.55;
    }

    @media (max-width: 1200px) {
      .shell {
        grid-template-columns: 1fr;
      }

      .sidebar {
        min-height: auto;
        position: static;
        border-right: 0;
        border-bottom: 1px solid rgba(255, 255, 255, 0.56);
      }

      .overview-grid,
      .placeholder-grid,
      .users-layout {
        grid-template-columns: 1fr;
      }
    }

    @media (max-width: 780px) {
      .main {
        padding: 16px 14px 28px;
      }

      .topbar {
        flex-direction: column;
      }

      .top-actions {
        justify-content: flex-start;
      }

      .metrics-grid,
      .grid-2,
      .placeholder-grid,
      .toolbar {
        grid-template-columns: 1fr;
      }

      .panel-head,
      .panel-body {
        padding-left: 16px;
        padding-right: 16px;
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark">QT</div>
        <div class="brand-copy">
          <strong>QT Server</strong>
          <span>Admin Console</span>
        </div>
      </div>
      <nav class="nav">
)HTML";
    append_admin_nav_link(html, kind, admin_page_kind::overview);
    append_admin_nav_link(html, kind, admin_page_kind::users);
    append_admin_nav_link(html, kind, admin_page_kind::groups);
    append_admin_nav_link(html, kind, admin_page_kind::conversations);
    append_admin_nav_link(html, kind, admin_page_kind::sessions);
    append_admin_nav_link(html, kind, admin_page_kind::files);
    html << R"HTML(
      </nav>
      <section class="side-note">
        <h2>当前边界</h2>
        <p>所有改动仅作用于 <code>/admin/*</code>，不会改动 <code>/upload/chat-file</code>、<code>/download/chat-file/*</code> 与 <code>/upload/avatar</code> 的现有行为。</p>
      </section>
    </aside>

    <main class="main">
      <header class="topbar">
        <div>
          <span class="eyebrow">)HTML" << meta.eyebrow << R"HTML(</span>
          <h1>)HTML" << meta.heading << R"HTML(</h1>
          <p>)HTML" << meta.summary << R"HTML(</p>
        </div>
        <div class="top-actions">
          <span class="pill" id="adminBadge">当前管理员: 加载中</span>
          <button id="logoutBtn" type="button" class="ghost-btn">退出登录</button>
        </div>
      </header>

      <div id="pageFlash" class="flash"></div>

      <div class="content">
)HTML" << body_html << R"HTML(
      </div>
    </main>
  </div>

  <script>
    (function () {
      const flashEl = document.getElementById("pageFlash");

      function escapeHtml(value) {
        return String(value == null ? "" : value)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#39;");
      }

      function setFlash(message, type) {
        if (!message) {
          flashEl.textContent = "";
          flashEl.className = "flash";
          return;
        }
        flashEl.textContent = message;
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

      function renderAdminBadge(admin) {
        const badge = document.getElementById("adminBadge");
        if (!admin) {
          badge.textContent = "当前管理员: 未登录";
          return;
        }
        const displayName = admin.display_name || admin.username;
        badge.innerHTML = "当前管理员: <strong>" + escapeHtml(displayName) + "</strong>";
      }

      async function loadSession() {
        const payload = await api("/admin/api/session/me");
        renderAdminBadge(payload.admin || null);
        return payload.admin || null;
      }

      document.getElementById("logoutBtn").addEventListener("click", function () {
        api("/admin/api/session/logout", { method: "POST" })
          .then(function () {
            window.location.replace("/admin/login");
          })
          .catch(function () {
            window.location.replace("/admin/login");
          });
      });

      window.__adminShell = {
        api: api,
        escapeHtml: escapeHtml,
        setFlash: setFlash,
        loadSession: loadSession
      };
    }());
  </script>
  <script>
)HTML" << page_script << R"HTML(
  </script>
</body>
</html>
)HTML";
    return html.str();
}

std::string build_placeholder_page_script(const char* message)
{
    std::ostringstream js;
    js << R"JS((function () {
  const shell = window.__adminShell;
  shell.loadSession()
    .then(function () {
      shell.setFlash(")JS" << message << R"JS(", "info");
    })
    .catch(function (error) {
      shell.setFlash(error.message, "error");
    });
}());)JS";
    return js.str();
}

} // namespace

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

    .card p {
      margin: 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.7;
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
  </style>
</head>
<body>
  <section class="card">
    <h2>管理员登录</h2>
    <p>后台入口已升级为多页面控制台，但所有变更仍严格限制在 <code>/admin/*</code>。</p>
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
          window.location.replace("/admin/overview");
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
        }).then(function (payload) {
          setFlash("登录成功，正在进入后台。", "info");
          window.location.replace(payload.redirect_to || "/admin/overview");
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

std::string build_dev_admin_overview_page()
{
    const std::string body = R"HTML(
<section class="panel">
  <div class="panel-head">
    <div>
      <h2>运行概览</h2>
      <p>这一页先接入用户域聚合数据，其它域按只读接口分阶段补齐。文件传输链路不在本轮变更范围内。</p>
    </div>
    <div class="actions">
      <button id="refreshOverviewBtn" type="button" class="primary-btn">刷新总览</button>
      <a class="ghost-btn" href="/admin/users">进入用户工作台</a>
    </div>
  </div>
  <div class="panel-body">
    <div class="metrics-grid">
      <div class="metric-card">
        <span>用户总数</span>
        <strong id="metricTotalUsers">-</strong>
      </div>
      <div class="metric-card">
        <span>启用账号</span>
        <strong id="metricEnabledUsers">-</strong>
      </div>
      <div class="metric-card">
        <span>禁用账号</span>
        <strong id="metricDisabledUsers">-</strong>
      </div>
      <div class="metric-card">
        <span>在线账号</span>
        <strong id="metricOnlineUsers">-</strong>
      </div>
      <div class="metric-card">
        <span>7 日内登录</span>
        <strong id="metricRecentLoginUsers">-</strong>
      </div>
      <div class="metric-card">
        <span>24 小时活跃</span>
        <strong id="metricRecentSeenUsers">-</strong>
      </div>
    </div>
  </div>
</section>

<div class="overview-grid">
  <section class="panel">
    <div class="panel-head">
      <div>
        <h2>最近活跃用户</h2>
        <p>用于快速进入排障入口。排序优先最近登录，其次创建时间。</p>
      </div>
    </div>
    <div class="panel-body">
      <div id="recentUsersList" class="recent-users">
        <div class="empty-state">正在加载最近用户。</div>
      </div>
    </div>
  </section>

  <div class="stack">
    <section class="panel">
      <div class="panel-head">
        <div>
          <h2>快捷入口</h2>
          <p>先把使用频率最高的入口放到总览里。</p>
        </div>
      </div>
      <div class="panel-body">
        <div class="action-links">
          <a class="action-link" href="/admin/users"><span>用户管理工作台</span><span>创建、编辑、重置密码</span></a>
          <a class="action-link" href="/admin/groups"><span>群组管理工作台</span><span>查看成员、群主与最近消息</span></a>
          <a class="action-link" href="/admin/conversations"><span>会话与消息诊断</span><span>按会话查看时间线与回执</span></a>
          <a class="action-link" href="/admin/files"><span>文件与头像中心</span><span>旁路查看元数据和后台下载</span></a>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <h2>实施顺序</h2>
          <p>先把价值高且低风险的只读能力补起来。</p>
        </div>
      </div>
      <div class="panel-body">
        <div class="note-grid">
          <p>阶段一：统一后台壳、总览、用户工作台。</p>
          <p>阶段二：群组、会话、在线状态页接入只读 API。</p>
          <p>阶段三：文件中心接元数据查询与后台专用下载，不动上传下载协议和路由。</p>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <h2>当前边界</h2>
          <p>总览页刻意只使用后台只读接口，不直接复用客户端 websocket 协议。</p>
        </div>
      </div>
      <div class="panel-body">
        <div class="status-strip">
          <strong>已接入</strong>
          <span class="muted">管理员会话、用户总览、群组检索、消息诊断、在线连接、文件元数据。</span>
        </div>
        <div class="status-strip">
          <strong>严格不动</strong>
          <span class="muted"><code>/upload/chat-file</code>、<code>/download/chat-file/*</code>、<code>/upload/avatar</code> 现有能力与协议保持不变。</span>
        </div>
      </div>
    </section>
  </div>
</div>
)HTML";

    const std::string script = R"JS((function () {
  const shell = window.__adminShell;

  function renderMetric(id, value) {
    const el = document.getElementById(id);
    if (el) {
      el.textContent = String(value == null ? "-" : value);
    }
  }

  function renderRecentUsers(users) {
    const container = document.getElementById("recentUsersList");
    if (!Array.isArray(users) || !users.length) {
      container.innerHTML = "<div class='empty-state'>当前没有可展示的用户数据。</div>";
      return;
    }

    container.innerHTML = users.map(function (user) {
      const displayName = user.nickname || user.username;
      const onlineClass = user.is_online ? "online" : "offline";
      const onlineLabel = user.is_online ? "在线" : "离线";
      const statusClass = Number(user.status) === 1 ? "enabled" : "disabled";
      const statusLabel = Number(user.status) === 1 ? "启用" : "禁用";
      return (
        "<div class='recent-user'>" +
          "<div class='recent-user-top'>" +
            "<strong>" + shell.escapeHtml(displayName) + "</strong>" +
            "<div class='actions'>" +
              "<span class='tag " + statusClass + "'>" + shell.escapeHtml(statusLabel) + "</span>" +
              "<span class='tag " + onlineClass + "'>" + shell.escapeHtml(onlineLabel) + "</span>" +
            "</div>" +
          "</div>" +
          "<p class='muted'>@" + shell.escapeHtml(user.username || "-") + " / user_id " + shell.escapeHtml(user.user_id || "-") + " / #" + shell.escapeHtml(user.numeric_id || "-") + "</p>" +
          "<p class='muted'>最近登录: " + shell.escapeHtml(user.last_login_at || "-") + "，最近在线: " + shell.escapeHtml(user.last_seen_at || "-") + "</p>" +
        "</div>"
      );
    }).join("");
  }

  async function loadOverview() {
    const payload = await shell.api("/admin/api/overview");
    const overview = payload.overview || {};
    renderMetric("metricTotalUsers", overview.total_users || 0);
    renderMetric("metricEnabledUsers", overview.enabled_users || 0);
    renderMetric("metricDisabledUsers", overview.disabled_users || 0);
    renderMetric("metricOnlineUsers", overview.online_users || 0);
    renderMetric("metricRecentLoginUsers", overview.recent_login_users || 0);
    renderMetric("metricRecentSeenUsers", overview.recent_seen_users || 0);
    renderRecentUsers(Array.isArray(overview.recent_users) ? overview.recent_users : []);
    shell.setFlash("总览数据已刷新。", "info");
  }

  document.getElementById("refreshOverviewBtn").addEventListener("click", function () {
    loadOverview().catch(function (error) {
      shell.setFlash(error.message, "error");
    });
  });

  shell.loadSession()
    .then(loadOverview)
    .catch(function (error) {
      shell.setFlash(error.message, "error");
    });
}());)JS";

    return build_admin_shell(admin_page_kind::overview, body, script);
}

std::string build_dev_user_admin_page()
{
    const std::string body = R"HTML(
<div class="users-layout">
  <section class="panel">
    <div class="panel-head">
      <div>
        <h2>用户列表</h2>
        <p>支持按 <code>user_id</code>、<code>numeric_id</code>、用户名、邮箱、昵称搜索。点击行后可在右侧编辑。</p>
      </div>
      <div class="actions">
        <button id="refreshBtn" type="button" class="primary-btn">刷新列表</button>
      </div>
    </div>
    <div class="panel-body">
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

      <div class="summary-row">
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

        <hr class="divider">

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
)HTML";

    const std::string script = R"JS((function () {
  const shell = window.__adminShell;
  const state = {
    users: [],
    selectedUserId: null
  };

  const usersBody = document.getElementById("usersBody");
  const countAll = document.getElementById("countAll");
  const countEnabled = document.getElementById("countEnabled");
  const countOnline = document.getElementById("countOnline");
  const saveUserBtn = document.getElementById("saveUserBtn");
  const resetPasswordBtn = document.getElementById("resetPasswordBtn");

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
      "<h3>" + shell.escapeHtml(user.nickname || user.username) + "</h3>" +
      "<p>" +
      "user_id: <strong>" + shell.escapeHtml(user.user_id) + "</strong> / " +
      "numeric_id: <strong>" + shell.escapeHtml(user.numeric_id) + "</strong><br>" +
      "username: <strong>" + shell.escapeHtml(user.username) + "</strong><br>" +
      "email: <strong>" + shell.escapeHtml(user.email || "-") + "</strong><br>" +
      "状态: <strong>" + shell.escapeHtml(statusLabel) + "</strong>，在线: <strong>" + shell.escapeHtml(onlineLabel) + "</strong><br>" +
      "最后登录: <strong>" + shell.escapeHtml(user.last_login_at || "-") + "</strong>" +
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
        "<tr class='" + (selected ? "selected" : "") + "' data-user-id='" + shell.escapeHtml(user.user_id) + "'>" +
          "<td><div class='user-main'><strong>" + shell.escapeHtml(user.username) + "</strong><span class='muted'>ID " + shell.escapeHtml(user.user_id) + " / #" + shell.escapeHtml(user.numeric_id) + "</span></div></td>" +
          "<td><div class='user-main'><strong>" + shell.escapeHtml(user.nickname || "-") + "</strong><span class='muted'>" + shell.escapeHtml(user.email || "-") + "</span></div></td>" +
          "<td><span class='tag " + statusClass + "'>" + shell.escapeHtml(statusLabel) + "</span></td>" +
          "<td><span class='tag " + onlineClass + "'>" + shell.escapeHtml(onlineLabel) + "</span></td>" +
          "<td>" + shell.escapeHtml(user.last_login_at || "-") + "</td>" +
          "<td>" + shell.escapeHtml(user.created_at || "-") + "</td>" +
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
    const payload = await shell.api("/admin/api/users?" + params.toString());
    state.users = Array.isArray(payload.users) ? payload.users : [];
    if (!state.users.some(function (user) { return String(user.user_id) === String(state.selectedUserId); })) {
      state.selectedUserId = state.users.length ? String(state.users[0].user_id) : null;
    }
    renderUsers();
    shell.setFlash("用户列表已刷新。", "info");
  }

  document.getElementById("refreshBtn").addEventListener("click", function () {
    loadUsers().catch(function (error) {
      shell.setFlash(error.message, "error");
    });
  });

  document.getElementById("searchForm").addEventListener("submit", function (event) {
    event.preventDefault();
    loadUsers().catch(function (error) {
      shell.setFlash(error.message, "error");
    });
  });

  document.getElementById("createForm").addEventListener("submit", function (event) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    shell.api("/admin/api/users", {
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
        shell.setFlash("用户创建成功。", "info");
      });
    }).catch(function (error) {
      shell.setFlash(error.message, "error");
    });
  });

  document.getElementById("editForm").addEventListener("submit", function (event) {
    event.preventDefault();
    const user = findSelectedUser();
    if (!user) {
      shell.setFlash("请先选择一个用户。", "error");
      return;
    }
    shell.api("/admin/api/users/" + encodeURIComponent(String(user.user_id)), {
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
        shell.setFlash("用户资料已更新。", "info");
      });
    }).catch(function (error) {
      shell.setFlash(error.message, "error");
    });
  });

  document.getElementById("resetPasswordForm").addEventListener("submit", function (event) {
    event.preventDefault();
    const user = findSelectedUser();
    if (!user) {
      shell.setFlash("请先选择一个用户。", "error");
      return;
    }
    shell.api("/admin/api/users/" + encodeURIComponent(String(user.user_id)) + "/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: document.getElementById("resetPasswordInput").value })
    }).then(function () {
      document.getElementById("resetPasswordInput").value = "";
      shell.setFlash("密码已重置。", "info");
    }).catch(function (error) {
      shell.setFlash(error.message, "error");
    });
  });

  shell.loadSession()
    .then(loadUsers)
    .catch(function (error) {
      shell.setFlash(error.message, "error");
    });
}());)JS";

    return build_admin_shell(admin_page_kind::users, body, script);
}

std::string build_dev_admin_groups_page()
{
    const std::string body = R"HTML(
<div class="users-layout">
  <section class="panel">
    <div class="panel-head">
      <div>
        <h2>群组列表</h2>
        <p>按群号、群名、群主筛选。点击左侧行后，右侧会加载群成员和最近消息。</p>
      </div>
      <div class="actions">
        <button id="refreshGroupsBtn" type="button" class="primary-btn">刷新群组</button>
      </div>
    </div>
    <div class="panel-body">
      <form id="groupSearchForm" class="grid-1">
        <div class="grid-2">
          <label>
            关键词
            <input id="groupKeywordInput" type="text" placeholder="群名 / 群主 / 会话 ID">
          </label>
          <label>
            群号
            <input id="groupNumericIdInput" type="text" placeholder="group_numeric_id">
          </label>
        </div>
        <div class="grid-2">
          <label>
            群主 user_id
            <input id="groupOwnerUserIdInput" type="text" placeholder="owner_user_id">
          </label>
          <label>
            返回条数
            <select id="groupLimitInput">
              <option value="20">20</option>
              <option value="50" selected>50</option>
              <option value="100">100</option>
            </select>
          </label>
        </div>
        <div class="actions">
          <button type="submit" class="primary-btn">查询群组</button>
        </div>
      </form>

      <div class="summary-row">
        <div class="summary-card">
          <strong id="groupCount">0</strong>
          <span>当前群组结果</span>
        </div>
      </div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>群组</th>
              <th>群主</th>
              <th>成员数</th>
              <th>最后消息</th>
              <th>更新时间</th>
            </tr>
          </thead>
          <tbody id="groupsBody">
            <tr><td colspan="5" class="muted">正在等待首次加载。</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <div class="stack">
    <section class="panel">
      <div class="panel-head">
        <div>
          <h2>群组概览</h2>
          <p>只读详情，不提供修改和成员操作。</p>
        </div>
      </div>
      <div class="panel-body">
        <div id="groupSelectedCard" class="selected-card">
          <h3>未选择群组</h3>
          <p>从左侧选中一个群组后，这里会显示群公告、群主和最后消息信息。</p>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <h2>群成员</h2>
          <p>显示角色、账号状态和在线状态。</p>
        </div>
      </div>
      <div class="panel-body">
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>成员</th>
                <th>账号状态</th>
                <th>在线</th>
                <th>角色</th>
                <th>最近在线</th>
              </tr>
            </thead>
            <tbody id="groupMembersBody">
              <tr><td colspan="5" class="muted">请先选择群组。</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <h2>最近消息</h2>
          <p>用于快速核对群最近的消息类型、发送者和送达情况。</p>
        </div>
      </div>
      <div class="panel-body">
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Seq</th>
                <th>发送者</th>
                <th>类型</th>
                <th>内容摘要</th>
                <th>发送时间</th>
                <th>回执</th>
              </tr>
            </thead>
            <tbody id="groupMessagesBody">
              <tr><td colspan="6" class="muted">请先选择群组。</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>
  </div>
</div>
)HTML";

    const std::string script = R"JS((function () {
  const shell = window.__adminShell;
  const state = {
    groups: [],
    selectedConversationId: null,
    group: null,
    members: [],
    messages: []
  };

  const groupsBody = document.getElementById("groupsBody");
  const membersBody = document.getElementById("groupMembersBody");
  const messagesBody = document.getElementById("groupMessagesBody");
  const groupCount = document.getElementById("groupCount");

  function getSelectedListGroup() {
    return state.groups.find(function (group) {
      return String(group.conversation_id) === String(state.selectedConversationId);
    }) || null;
  }

  function renderGroupCard() {
    const card = document.getElementById("groupSelectedCard");
    const group = state.group || getSelectedListGroup();
    if (!group) {
      card.innerHTML = "<h3>未选择群组</h3><p>从左侧选中一个群组后，这里会显示群公告、群主和最后消息信息。</p>";
      return;
    }
    const notice = group.notice ? shell.escapeHtml(group.notice) : "暂无群公告";
    card.innerHTML =
      "<h3>" + shell.escapeHtml(group.name || ("群 " + (group.group_numeric_id || "-"))) + "</h3>" +
      "<div class='detail-list'>" +
        "<p class='muted mono'>conversation_id: " + shell.escapeHtml(group.conversation_id || "-") + "</p>" +
        "<p>群号 <strong>" + shell.escapeHtml(group.group_numeric_id || "-") + "</strong>，成员 <strong>" + shell.escapeHtml(group.member_count || "0") + "</strong> 人</p>" +
        "<p>群主: <strong>" + shell.escapeHtml(group.owner_nickname || group.owner_username || "-") + "</strong> / @" + shell.escapeHtml(group.owner_username || "-") + " / user_id " + shell.escapeHtml(group.owner_user_id || "-") + "</p>" +
        "<p>最后消息 seq: <strong>" + shell.escapeHtml(group.last_message_seq || "0") + "</strong>，时间: <strong>" + shell.escapeHtml(group.last_message_sent_at || "-") + "</strong></p>" +
        "<p class='pre-wrap'>" + notice + "</p>" +
      "</div>";
  }

  function renderMembers() {
    if (!state.members.length) {
      membersBody.innerHTML = "<tr><td colspan='5' class='muted'>当前群组没有成员数据。</td></tr>";
      return;
    }
    membersBody.innerHTML = state.members.map(function (member) {
      const statusClass = Number(member.status) === 1 ? "enabled" : "disabled";
      const statusLabel = Number(member.status) === 1 ? "启用" : "禁用";
      const onlineClass = member.is_online ? "online" : "offline";
      const onlineLabel = member.is_online ? "在线" : "离线";
      const roleLabel = Number(member.role) >= 2 ? "群主" : (Number(member.role) === 1 ? "管理员" : "成员");
      return (
        "<tr>" +
          "<td><div class='user-main'><strong>" + shell.escapeHtml(member.nickname || member.username || "-") + "</strong><span class='muted'>@" + shell.escapeHtml(member.username || "-") + " / #" + shell.escapeHtml(member.numeric_id || "-") + "</span></div></td>" +
          "<td><span class='tag " + statusClass + "'>" + shell.escapeHtml(statusLabel) + "</span></td>" +
          "<td><span class='tag " + onlineClass + "'>" + shell.escapeHtml(onlineLabel) + "</span></td>" +
          "<td>" + shell.escapeHtml(roleLabel) + "</td>" +
          "<td>" + shell.escapeHtml(member.last_seen_at || "-") + "</td>" +
        "</tr>"
      );
    }).join("");
  }

  function renderMessages() {
    if (!state.messages.length) {
      messagesBody.innerHTML = "<tr><td colspan='6' class='muted'>当前群组还没有可显示的最近消息。</td></tr>";
      return;
    }
    messagesBody.innerHTML = state.messages.map(function (message) {
      const sender = message.sender_username ? ("@" + message.sender_username) : "-";
      const receiptLabel = String(message.delivered_count || 0) + " / " + String(message.receipt_total || 0);
      return (
        "<tr>" +
          "<td class='mono'>" + shell.escapeHtml(message.seq || "-") + "</td>" +
          "<td><div class='user-main'><strong>" + shell.escapeHtml(sender) + "</strong><span class='muted'>user_id " + shell.escapeHtml(message.sender_user_id || "-") + "</span></div></td>" +
          "<td>" + shell.escapeHtml(message.message_kind || "-") + "</td>" +
          "<td><div class='content-snippet'>" + shell.escapeHtml(message.content_preview || "-") + "</div></td>" +
          "<td>" + shell.escapeHtml(message.sent_at || "-") + "</td>" +
          "<td>" + shell.escapeHtml(receiptLabel) + "</td>" +
        "</tr>"
      );
    }).join("");
  }

  function renderGroups() {
    groupCount.textContent = String(state.groups.length);
    if (!state.groups.length) {
      groupsBody.innerHTML = "<tr><td colspan='5' class='muted'>没有匹配的群组记录。</td></tr>";
      state.group = null;
      state.members = [];
      state.messages = [];
      renderGroupCard();
      renderMembers();
      renderMessages();
      return;
    }

    groupsBody.innerHTML = state.groups.map(function (group) {
      const selected = String(group.conversation_id) === String(state.selectedConversationId);
      const ownerName = group.owner_nickname || group.owner_username || "-";
      return (
        "<tr class='" + (selected ? "selected" : "") + "' data-conversation-id='" + shell.escapeHtml(group.conversation_id) + "'>" +
          "<td><div class='user-main'><strong>" + shell.escapeHtml(group.name || ("群 " + (group.group_numeric_id || "-"))) + "</strong><span class='muted mono'>CID " + shell.escapeHtml(group.conversation_id || "-") + " / #" + shell.escapeHtml(group.group_numeric_id || "-") + "</span></div></td>" +
          "<td><div class='user-main'><strong>" + shell.escapeHtml(ownerName) + "</strong><span class='muted'>@" + shell.escapeHtml(group.owner_username || "-") + " / user_id " + shell.escapeHtml(group.owner_user_id || "-") + "</span></div></td>" +
          "<td>" + shell.escapeHtml(group.member_count || "0") + "</td>" +
          "<td class='mono'>" + shell.escapeHtml(group.last_message_seq || "0") + "</td>" +
          "<td>" + shell.escapeHtml(group.updated_at || "-") + "</td>" +
        "</tr>"
      );
    }).join("");

    Array.prototype.forEach.call(groupsBody.querySelectorAll("tr[data-conversation-id]"), function (row) {
      row.addEventListener("click", function () {
        const conversationId = row.getAttribute("data-conversation-id");
        state.selectedConversationId = conversationId;
        renderGroups();
        loadGroupDetail(conversationId).catch(function (error) {
          shell.setFlash(error.message, "error");
        });
      });
    });
  }

  async function loadGroupDetail(conversationId) {
    if (!conversationId) {
      state.group = null;
      state.members = [];
      state.messages = [];
      renderGroupCard();
      renderMembers();
      renderMessages();
      return;
    }
    const payload = await shell.api("/admin/api/groups/" + encodeURIComponent(conversationId));
    if (String(state.selectedConversationId) !== String(conversationId)) {
      return;
    }
    state.group = payload.group || null;
    state.members = Array.isArray(payload.members) ? payload.members : [];
    state.messages = Array.isArray(payload.recent_messages) ? payload.recent_messages : [];
    renderGroupCard();
    renderMembers();
    renderMessages();
  }

  async function loadGroups(showFlash) {
    const params = new URLSearchParams();
    const keyword = document.getElementById("groupKeywordInput").value.trim();
    const groupNumericId = document.getElementById("groupNumericIdInput").value.trim();
    const ownerUserId = document.getElementById("groupOwnerUserIdInput").value.trim();
    if (keyword) {
      params.set("keyword", keyword);
    }
    if (groupNumericId) {
      params.set("group_numeric_id", groupNumericId);
    }
    if (ownerUserId) {
      params.set("owner_user_id", ownerUserId);
    }
    params.set("limit", document.getElementById("groupLimitInput").value);

    const payload = await shell.api("/admin/api/groups?" + params.toString());
    state.groups = Array.isArray(payload.groups) ? payload.groups : [];
    if (!state.groups.some(function (group) { return String(group.conversation_id) === String(state.selectedConversationId); })) {
      state.selectedConversationId = state.groups.length ? String(state.groups[0].conversation_id) : null;
    }
    renderGroups();
    if (state.selectedConversationId) {
      await loadGroupDetail(state.selectedConversationId);
    }
    if (showFlash) {
      shell.setFlash(state.groups.length ? "群组数据已刷新。" : "没有匹配的群组记录。", "info");
    }
  }

  document.getElementById("groupSearchForm").addEventListener("submit", function (event) {
    event.preventDefault();
    loadGroups(true).catch(function (error) {
      shell.setFlash(error.message, "error");
    });
  });

  document.getElementById("refreshGroupsBtn").addEventListener("click", function () {
    loadGroups(true).catch(function (error) {
      shell.setFlash(error.message, "error");
    });
  });

  shell.loadSession()
    .then(function () { return loadGroups(false); })
    .catch(function (error) {
      shell.setFlash(error.message, "error");
    });
}());)JS";

    return build_admin_shell(admin_page_kind::groups, body, script);
}

std::string build_dev_admin_conversations_page()
{
    const std::string body = R"HTML(
<div class="users-layout">
  <section class="panel">
    <div class="panel-head">
      <div>
        <h2>会话检索</h2>
        <p>按会话 ID、成员 user_id / numeric_id、群号或关键词筛选会话。</p>
      </div>
      <div class="actions">
        <button id="refreshConversationsBtn" type="button" class="primary-btn">刷新会话</button>
      </div>
    </div>
    <div class="panel-body">
      <form id="conversationSearchForm" class="grid-1">
        <div class="grid-2">
          <label>
            关键词
            <input id="conversationKeywordInput" type="text" placeholder="会话名 / 成员用户名 / 昵称">
          </label>
          <label>
            会话 ID
            <input id="conversationIdInput" type="text" placeholder="conversation_id">
          </label>
        </div>
        <div class="grid-2">
          <label>
            成员 user_id
            <input id="conversationUserIdInput" type="text" placeholder="user_id">
          </label>
          <label>
            成员 numeric_id
            <input id="conversationNumericIdInput" type="text" placeholder="numeric_id">
          </label>
        </div>
        <div class="grid-2">
          <label>
            群号
            <input id="conversationGroupNumericIdInput" type="text" placeholder="group_numeric_id">
          </label>
          <label>
            返回条数
            <select id="conversationLimitInput">
              <option value="20">20</option>
              <option value="50" selected>50</option>
              <option value="100">100</option>
            </select>
          </label>
        </div>
        <div class="actions">
          <button type="submit" class="primary-btn">查询会话</button>
        </div>
      </form>

      <div class="summary-row">
        <div class="summary-card">
          <strong id="conversationCount">0</strong>
          <span>当前会话结果</span>
        </div>
        <div class="summary-card">
          <strong id="messageCount">0</strong>
          <span>当前消息条数</span>
        </div>
      </div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>会话</th>
              <th>类型</th>
              <th>成员</th>
              <th>最后消息</th>
              <th>更新时间</th>
            </tr>
          </thead>
          <tbody id="conversationsBody">
            <tr><td colspan="5" class="muted">正在等待首次加载。</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <div class="stack">
    <section class="panel">
      <div class="panel-head">
        <div>
          <h2>会话概览</h2>
          <p>展示当前会话的基础属性和参与者摘要。</p>
        </div>
      </div>
      <div class="panel-body">
        <div id="conversationSelectedCard" class="selected-card">
          <h3>未选择会话</h3>
          <p>从左侧选择会话后，这里会显示会话类型、成员数和参与者摘要。</p>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <h2>消息时间线</h2>
          <p>点击消息后，下面会加载送达回执。</p>
        </div>
      </div>
      <div class="panel-body">
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Seq</th>
                <th>发送者</th>
                <th>类型</th>
                <th>内容摘要</th>
                <th>发送时间</th>
                <th>回执</th>
              </tr>
            </thead>
            <tbody id="conversationMessagesBody">
              <tr><td colspan="6" class="muted">请先选择会话。</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <h2>消息回执</h2>
          <p>针对当前选中消息，查看哪些接收者已经送达。</p>
        </div>
      </div>
      <div class="panel-body">
        <div id="receiptSelectedCard" class="compact-card muted">请先在上方消息列表中选择一条消息。</div>
        <div class="table-wrap" style="margin-top: 14px;">
          <table>
            <thead>
              <tr>
                <th>接收者</th>
                <th>numeric_id</th>
                <th>状态</th>
                <th>送达时间</th>
              </tr>
            </thead>
            <tbody id="conversationReceiptsBody">
              <tr><td colspan="4" class="muted">请先选择消息。</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>
  </div>
</div>
)HTML";

    const std::string script = R"JS((function () {
  const shell = window.__adminShell;
  const state = {
    conversations: [],
    selectedConversationId: null,
    conversation: null,
    messages: [],
    selectedMessageId: null,
    receipts: []
  };

  const conversationsBody = document.getElementById("conversationsBody");
  const messagesBody = document.getElementById("conversationMessagesBody");
  const receiptsBody = document.getElementById("conversationReceiptsBody");
  const conversationCount = document.getElementById("conversationCount");
  const messageCount = document.getElementById("messageCount");

  function getSelectedConversationFromList() {
    return state.conversations.find(function (conversation) {
      return String(conversation.conversation_id) === String(state.selectedConversationId);
    }) || null;
  }

  function getSelectedMessage() {
    return state.messages.find(function (message) {
      return String(message.message_id) === String(state.selectedMessageId);
    }) || null;
  }

  function conversationTypeLabel(conversation) {
    return Number(conversation.conversation_type) === 2 ? "群聊" : "单聊";
  }

  function renderConversationCard() {
    const card = document.getElementById("conversationSelectedCard");
    const conversation = state.conversation || getSelectedConversationFromList();
    if (!conversation) {
      card.innerHTML = "<h3>未选择会话</h3><p>从左侧选择会话后，这里会显示会话类型、成员数和参与者摘要。</p>";
      return;
    }
    card.innerHTML =
      "<h3>" + shell.escapeHtml(conversation.name || conversation.conversation_id || "-") + "</h3>" +
      "<div class='detail-list'>" +
        "<p class='muted mono'>conversation_id: " + shell.escapeHtml(conversation.conversation_id || "-") + "</p>" +
        "<p>类型: <strong>" + shell.escapeHtml(conversationTypeLabel(conversation)) + "</strong>，成员数: <strong>" + shell.escapeHtml(conversation.member_count || "0") + "</strong></p>" +
        "<p>群号: <strong>" + shell.escapeHtml(conversation.group_numeric_id || "-") + "</strong>，群主 user_id: <strong>" + shell.escapeHtml(conversation.owner_user_id || "-") + "</strong></p>" +
        "<p>最后消息 seq: <strong>" + shell.escapeHtml(conversation.last_message_seq || "0") + "</strong>，时间: <strong>" + shell.escapeHtml(conversation.last_message_sent_at || "-") + "</strong></p>" +
        "<p class='pre-wrap'>" + shell.escapeHtml(conversation.participants_summary || "暂无参与者摘要") + "</p>" +
      "</div>";
  }

  function renderConversations() {
    conversationCount.textContent = String(state.conversations.length);
    if (!state.conversations.length) {
      conversationsBody.innerHTML = "<tr><td colspan='5' class='muted'>没有匹配的会话记录。</td></tr>";
      state.conversation = null;
      state.messages = [];
      state.receipts = [];
      state.selectedMessageId = null;
      renderConversationCard();
      renderMessages();
      renderReceipts();
      return;
    }

    conversationsBody.innerHTML = state.conversations.map(function (conversation) {
      const selected = String(conversation.conversation_id) === String(state.selectedConversationId);
      return (
        "<tr class='" + (selected ? "selected" : "") + "' data-conversation-id='" + shell.escapeHtml(conversation.conversation_id) + "'>" +
          "<td><div class='user-main'><strong>" + shell.escapeHtml(conversation.name || conversation.conversation_id || "-") + "</strong><span class='muted mono'>CID " + shell.escapeHtml(conversation.conversation_id || "-") + "</span></div></td>" +
          "<td>" + shell.escapeHtml(conversationTypeLabel(conversation)) + "</td>" +
          "<td>" + shell.escapeHtml(conversation.member_count || "0") + "</td>" +
          "<td class='mono'>" + shell.escapeHtml(conversation.last_message_seq || "0") + "</td>" +
          "<td>" + shell.escapeHtml(conversation.updated_at || "-") + "</td>" +
        "</tr>"
      );
    }).join("");

    Array.prototype.forEach.call(conversationsBody.querySelectorAll("tr[data-conversation-id]"), function (row) {
      row.addEventListener("click", function () {
        const conversationId = row.getAttribute("data-conversation-id");
        state.selectedConversationId = conversationId;
        state.selectedMessageId = null;
        state.receipts = [];
        renderConversations();
        loadConversationWorkspace(conversationId).catch(function (error) {
          shell.setFlash(error.message, "error");
        });
      });
    });
  }

  function renderMessages() {
    messageCount.textContent = String(state.messages.length);
    if (!state.messages.length) {
      messagesBody.innerHTML = "<tr><td colspan='6' class='muted'>当前会话没有消息数据。</td></tr>";
      return;
    }

    messagesBody.innerHTML = state.messages.map(function (message) {
      const selected = String(message.message_id) === String(state.selectedMessageId);
      const receiptLabel = String(message.delivered_count || 0) + " / " + String(message.receipt_total || 0);
      return (
        "<tr class='" + (selected ? "selected" : "") + "' data-message-id='" + shell.escapeHtml(message.message_id) + "'>" +
          "<td class='mono'>" + shell.escapeHtml(message.seq || "-") + "</td>" +
          "<td><div class='user-main'><strong>@" + shell.escapeHtml(message.sender_username || "-") + "</strong><span class='muted'>user_id " + shell.escapeHtml(message.sender_user_id || "-") + "</span></div></td>" +
          "<td>" + shell.escapeHtml(message.message_kind || "-") + "</td>" +
          "<td><div class='content-snippet'>" + shell.escapeHtml(message.content_preview || "-") + "</div></td>" +
          "<td>" + shell.escapeHtml(message.sent_at || "-") + "</td>" +
          "<td>" + shell.escapeHtml(receiptLabel) + "</td>" +
        "</tr>"
      );
    }).join("");

    Array.prototype.forEach.call(messagesBody.querySelectorAll("tr[data-message-id]"), function (row) {
      row.addEventListener("click", function () {
        const messageId = row.getAttribute("data-message-id");
        state.selectedMessageId = messageId;
        renderMessages();
        loadReceipts(messageId).catch(function (error) {
          shell.setFlash(error.message, "error");
        });
      });
    });
  }

  function renderReceipts() {
    const selectedCard = document.getElementById("receiptSelectedCard");
    const message = getSelectedMessage();
    if (!message) {
      selectedCard.textContent = "请先在上方消息列表中选择一条消息。";
      receiptsBody.innerHTML = "<tr><td colspan='4' class='muted'>请先选择消息。</td></tr>";
      return;
    }
    selectedCard.innerHTML =
      "当前消息: <span class='mono'>" + shell.escapeHtml(message.message_id || "-") + "</span> / seq " +
      "<strong>" + shell.escapeHtml(message.seq || "-") + "</strong> / 类型 " +
      "<strong>" + shell.escapeHtml(message.message_kind || "-") + "</strong>";

    if (!state.receipts.length) {
      receiptsBody.innerHTML = "<tr><td colspan='4' class='muted'>当前消息没有回执记录或无需回执。</td></tr>";
      return;
    }
    receiptsBody.innerHTML = state.receipts.map(function (receipt) {
      const deliveredClass = receipt.delivered ? "online" : "offline";
      const deliveredLabel = receipt.delivered ? "已送达" : "未送达";
      return (
        "<tr>" +
          "<td><div class='user-main'><strong>" + shell.escapeHtml(receipt.nickname || receipt.username || "-") + "</strong><span class='muted'>@" + shell.escapeHtml(receipt.username || "-") + "</span></div></td>" +
          "<td>" + shell.escapeHtml(receipt.numeric_id || "-") + "</td>" +
          "<td><span class='tag " + deliveredClass + "'>" + shell.escapeHtml(deliveredLabel) + "</span></td>" +
          "<td>" + shell.escapeHtml(receipt.delivered_at || "-") + "</td>" +
        "</tr>"
      );
    }).join("");
  }

  async function loadReceipts(messageId) {
    if (!state.selectedConversationId || !messageId) {
      state.receipts = [];
      renderReceipts();
      return;
    }
    const payload = await shell.api(
      "/admin/api/conversations/" + encodeURIComponent(state.selectedConversationId) +
      "/receipts?message_id=" + encodeURIComponent(messageId)
    );
    if (String(state.selectedMessageId) !== String(messageId)) {
      return;
    }
    state.receipts = Array.isArray(payload.receipts) ? payload.receipts : [];
    renderReceipts();
  }

  async function loadConversationWorkspace(conversationId) {
    if (!conversationId) {
      state.conversation = null;
      state.messages = [];
      state.selectedMessageId = null;
      state.receipts = [];
      renderConversationCard();
      renderMessages();
      renderReceipts();
      return;
    }
    const limit = document.getElementById("conversationLimitInput").value;
    const payload = await shell.api("/admin/api/conversations/" + encodeURIComponent(conversationId) + "/messages?limit=" + encodeURIComponent(limit));
    if (String(state.selectedConversationId) !== String(conversationId)) {
      return;
    }
    state.conversation = payload.conversation || null;
    state.messages = Array.isArray(payload.messages) ? payload.messages : [];
    if (!state.messages.some(function (message) { return String(message.message_id) === String(state.selectedMessageId); })) {
      state.selectedMessageId = state.messages.length ? String(state.messages[0].message_id) : null;
    }
    state.receipts = [];
    renderConversationCard();
    renderMessages();
    renderReceipts();
    if (state.selectedMessageId) {
      await loadReceipts(state.selectedMessageId);
    }
  }

  async function loadConversations(showFlash) {
    const params = new URLSearchParams();
    const keyword = document.getElementById("conversationKeywordInput").value.trim();
    const conversationId = document.getElementById("conversationIdInput").value.trim();
    const userId = document.getElementById("conversationUserIdInput").value.trim();
    const numericId = document.getElementById("conversationNumericIdInput").value.trim();
    const groupNumericId = document.getElementById("conversationGroupNumericIdInput").value.trim();
    if (keyword) {
      params.set("keyword", keyword);
    }
    if (conversationId) {
      params.set("conversation_id", conversationId);
    }
    if (userId) {
      params.set("user_id", userId);
    }
    if (numericId) {
      params.set("numeric_id", numericId);
    }
    if (groupNumericId) {
      params.set("group_numeric_id", groupNumericId);
    }
    params.set("limit", document.getElementById("conversationLimitInput").value);

    const payload = await shell.api("/admin/api/conversations?" + params.toString());
    state.conversations = Array.isArray(payload.conversations) ? payload.conversations : [];
    if (!state.conversations.some(function (conversation) { return String(conversation.conversation_id) === String(state.selectedConversationId); })) {
      state.selectedConversationId = state.conversations.length ? String(state.conversations[0].conversation_id) : null;
    }
    renderConversations();
    await loadConversationWorkspace(state.selectedConversationId);
    if (showFlash) {
      shell.setFlash(state.conversations.length ? "会话与消息数据已刷新。" : "没有匹配的会话记录。", "info");
    }
  }

  document.getElementById("conversationSearchForm").addEventListener("submit", function (event) {
    event.preventDefault();
    loadConversations(true).catch(function (error) {
      shell.setFlash(error.message, "error");
    });
  });

  document.getElementById("refreshConversationsBtn").addEventListener("click", function () {
    loadConversations(true).catch(function (error) {
      shell.setFlash(error.message, "error");
    });
  });

  shell.loadSession()
    .then(function () { return loadConversations(false); })
    .catch(function (error) {
      shell.setFlash(error.message, "error");
    });
}());)JS";

    return build_admin_shell(admin_page_kind::conversations, body, script);
}

std::string build_dev_admin_sessions_page()
{
    const std::string body = R"HTML(
<section class="panel">
  <div class="panel-head">
    <div>
      <h2>在线态筛选</h2>
      <p>同时查看数据库在线字段与 websocket 运行时快照，不涉及任何消息或文件写入操作。</p>
    </div>
    <div class="actions">
      <button id="refreshSessionsBtn" type="button" class="primary-btn">刷新快照</button>
    </div>
  </div>
  <div class="panel-body">
    <form id="sessionsSearchForm" class="grid-1">
      <div class="grid-2">
        <label>
          关键词
          <input id="sessionsKeywordInput" type="text" placeholder="user_id / numeric_id / username / endpoint">
        </label>
        <label>
          返回条数
          <select id="sessionsLimitInput">
            <option value="50">50</option>
            <option value="100" selected>100</option>
            <option value="200">200</option>
          </select>
        </label>
      </div>
      <div class="actions">
        <label class="toolbar-inline">
          <input id="sessionsIncludeDisabledInput" type="checkbox" checked>
          包含已禁用用户
        </label>
        <label class="toolbar-inline">
          <input id="sessionsOnlineOnlyInput" type="checkbox">
          仅看有活跃连接的用户
        </label>
        <button type="submit" class="primary-btn">应用筛选</button>
      </div>
    </form>

    <div class="summary-row">
      <div class="summary-card">
        <strong id="sessionsUsersCount">0</strong>
        <span>用户结果数</span>
      </div>
      <div class="summary-card">
        <strong id="sessionsOnlineUsersCount">0</strong>
        <span>有活跃连接的用户</span>
      </div>
      <div class="summary-card">
        <strong id="sessionsConnectionsCount">0</strong>
        <span>实时连接总数</span>
      </div>
      <div class="summary-card">
        <strong id="sessionsMultiUserCount">0</strong>
        <span>多连接用户</span>
      </div>
    </div>
  </div>
</section>

<section class="panel">
  <div class="panel-head">
    <div>
      <h2>用户在线视图</h2>
      <p>这里的“活跃连接”来自 websocket 内存快照；“DB 在线”来自用户资料表。</p>
    </div>
  </div>
  <div class="panel-body">
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>用户</th>
            <th>账号状态</th>
            <th>DB 在线</th>
            <th>活跃连接</th>
            <th>最近在线</th>
            <th>最后登录</th>
          </tr>
        </thead>
        <tbody id="sessionsUsersBody">
          <tr><td colspan="6" class="muted">正在等待首次加载。</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</section>

<section class="panel">
  <div class="panel-head">
    <div>
      <h2>WebSocket 连接快照</h2>
      <p>只读展示远端地址、认证用户、最后活动时间和当前写队列状态。</p>
    </div>
  </div>
  <div class="panel-body">
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>远端地址</th>
            <th>认证用户</th>
            <th>状态</th>
            <th>待写队列</th>
            <th>连接时间</th>
            <th>最后活动</th>
          </tr>
        </thead>
        <tbody id="sessionsConnectionsBody">
          <tr><td colspan="6" class="muted">正在等待首次加载。</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</section>
)HTML";

    const std::string script = R"JS((function () {
  const shell = window.__adminShell;
  const state = {
    users: [],
    connections: [],
    counts: {
      users: 0,
      onlineUsers: 0,
      connections: 0,
      multiUsers: 0
    }
  };

  const usersBody = document.getElementById("sessionsUsersBody");
  const connectionsBody = document.getElementById("sessionsConnectionsBody");

  function renderCounts() {
    document.getElementById("sessionsUsersCount").textContent = String(state.counts.users || 0);
    document.getElementById("sessionsOnlineUsersCount").textContent = String(state.counts.onlineUsers || 0);
    document.getElementById("sessionsConnectionsCount").textContent = String(state.counts.connections || 0);
    document.getElementById("sessionsMultiUserCount").textContent = String(state.counts.multiUsers || 0);
  }

  function renderUsers() {
    if (!state.users.length) {
      usersBody.innerHTML = "<tr><td colspan='6' class='muted'>没有匹配的用户在线记录。</td></tr>";
      return;
    }
    usersBody.innerHTML = state.users.map(function (user) {
      const statusClass = Number(user.status) === 1 ? "enabled" : "disabled";
      const statusLabel = Number(user.status) === 1 ? "启用" : "禁用";
      const dbOnlineClass = user.is_online ? "online" : "offline";
      const dbOnlineLabel = user.is_online ? "在线" : "离线";
      const activeSessions = Number(user.active_sessions || 0);
      const mismatch = Boolean(user.presence_mismatch);
      return (
        "<tr>" +
          "<td><div class='user-main'><strong>" + shell.escapeHtml(user.nickname || user.username || "-") + "</strong><span class='muted'>@" + shell.escapeHtml(user.username || "-") + " / user_id " + shell.escapeHtml(user.user_id || "-") + " / #" + shell.escapeHtml(user.numeric_id || "-") + "</span></div></td>" +
          "<td><span class='tag " + statusClass + "'>" + shell.escapeHtml(statusLabel) + "</span></td>" +
          "<td><span class='tag " + dbOnlineClass + "'>" + shell.escapeHtml(dbOnlineLabel) + "</span></td>" +
          "<td><div class='inline-meta'><strong>" + shell.escapeHtml(String(activeSessions)) + "</strong>" + (mismatch ? "<span class='tag disabled'>状态不一致</span>" : "") + "</div></td>" +
          "<td>" + shell.escapeHtml(user.last_seen_at || "-") + "</td>" +
          "<td>" + shell.escapeHtml(user.last_login_at || "-") + "</td>" +
        "</tr>"
      );
    }).join("");
  }

  function renderConnections() {
    if (!state.connections.length) {
      connectionsBody.innerHTML = "<tr><td colspan='6' class='muted'>当前没有实时连接快照。</td></tr>";
      return;
    }
    connectionsBody.innerHTML = state.connections.map(function (connection) {
      const authenticated = connection.authenticated_user_id && connection.authenticated_user_id !== "0";
      const userLabel = authenticated
        ? ("@" + (connection.authenticated_username || "-") + " / user_id " + (connection.authenticated_user_id || "-") + " / #" + (connection.authenticated_numeric_id || "-"))
        : "未认证连接";
      return (
        "<tr>" +
          "<td class='mono'>" + shell.escapeHtml(connection.remote_endpoint || "-") + "</td>" +
          "<td>" + shell.escapeHtml(userLabel) + "</td>" +
          "<td>" + shell.escapeHtml(connection.state || "-") + "</td>" +
          "<td>" + shell.escapeHtml(String(connection.pending_writes || 0)) + (connection.write_in_progress ? " / 写入中" : "") + "</td>" +
          "<td>" + shell.escapeHtml(connection.connected_at || "-") + "</td>" +
          "<td>" + shell.escapeHtml(connection.last_activity_at || "-") + "</td>" +
        "</tr>"
      );
    }).join("");
  }

  async function loadSessions(showFlash) {
    const params = new URLSearchParams();
    const keyword = document.getElementById("sessionsKeywordInput").value.trim();
    if (keyword) {
      params.set("keyword", keyword);
    }
    params.set("limit", document.getElementById("sessionsLimitInput").value);
    params.set("include_disabled", document.getElementById("sessionsIncludeDisabledInput").checked ? "1" : "0");
    params.set("online_only", document.getElementById("sessionsOnlineOnlyInput").checked ? "1" : "0");

    const payload = await shell.api("/admin/api/sessions?" + params.toString());
    state.users = Array.isArray(payload.users) ? payload.users : [];
    state.connections = Array.isArray(payload.connections) ? payload.connections : [];
    state.counts.users = Number(payload.users_count || state.users.length || 0);
    state.counts.onlineUsers = Number(payload.online_users_count || 0);
    state.counts.connections = Number(payload.connections_count || state.connections.length || 0);
    state.counts.multiUsers = Number(payload.multi_session_users_count || 0);
    renderCounts();
    renderUsers();
    renderConnections();
    if (showFlash) {
      shell.setFlash("在线状态与连接快照已刷新。", "info");
    }
  }

  document.getElementById("sessionsSearchForm").addEventListener("submit", function (event) {
    event.preventDefault();
    loadSessions(true).catch(function (error) {
      shell.setFlash(error.message, "error");
    });
  });

  document.getElementById("refreshSessionsBtn").addEventListener("click", function () {
    loadSessions(true).catch(function (error) {
      shell.setFlash(error.message, "error");
    });
  });

  shell.loadSession()
    .then(function () { return loadSessions(false); })
    .catch(function (error) {
      shell.setFlash(error.message, "error");
    });
}());)JS";

    return build_admin_shell(admin_page_kind::sessions, body, script);
}

std::string build_dev_admin_files_page()
{
    const std::string body = R"HTML(
<section class="panel">
  <div class="panel-head">
    <div>
      <h2>头像索引</h2>
      <p>读取用户资料和本地头像文件状态，便于检查头像是否落盘、路径是否一致。</p>
    </div>
    <div class="actions">
      <button id="refreshAvatarsBtn" type="button" class="primary-btn">刷新头像</button>
    </div>
  </div>
  <div class="panel-body">
    <form id="avatarSearchForm" class="grid-1">
      <div class="grid-2">
        <label>
          关键词
          <input id="avatarKeywordInput" type="text" placeholder="user_id / numeric_id / username / nickname">
        </label>
        <label>
          返回条数
          <select id="avatarLimitInput">
            <option value="50">50</option>
            <option value="100" selected>100</option>
            <option value="200">200</option>
          </select>
        </label>
      </div>
      <div class="actions">
        <label class="toolbar-inline">
          <input id="avatarIncludeDisabledInput" type="checkbox" checked>
          包含已禁用用户
        </label>
        <button type="submit" class="primary-btn">查询头像</button>
      </div>
    </form>

    <div class="summary-row">
      <div class="summary-card">
        <strong id="avatarCount">0</strong>
        <span>头像结果数</span>
      </div>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>用户</th>
            <th>本地预览</th>
            <th>资料 avatar_url</th>
            <th>文件状态</th>
            <th>大小</th>
            <th>更新时间</th>
          </tr>
        </thead>
        <tbody id="avatarsBody">
          <tr><td colspan="6" class="muted">正在等待首次加载。</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</section>

<section class="panel">
  <div class="panel-head">
    <div>
      <h2>聊天文件索引</h2>
      <p>读取聊天文件元数据和本地文件状态，后台下载走独立管理路由。</p>
    </div>
    <div class="actions">
      <button id="refreshChatFilesBtn" type="button" class="primary-btn">刷新文件</button>
    </div>
  </div>
  <div class="panel-body">
    <form id="chatFileSearchForm" class="grid-1">
      <div class="grid-2">
        <label>
          关键词
          <input id="chatFileKeywordInput" type="text" placeholder="file_id / 原始文件名 / sha256">
        </label>
        <label>
          会话 ID
          <input id="chatFileConversationIdInput" type="text" placeholder="conversation_id">
        </label>
      </div>
      <div class="grid-2">
        <label>
          上传者 user_id
          <input id="chatFileUploaderUserIdInput" type="text" placeholder="uploader_user_id">
        </label>
        <label>
          file_id
          <input id="chatFileIdInput" type="text" placeholder="file_id">
        </label>
      </div>
      <div class="grid-2">
        <label>
          返回条数
          <select id="chatFileLimitInput">
            <option value="20">20</option>
            <option value="50" selected>50</option>
            <option value="100">100</option>
          </select>
        </label>
        <div></div>
      </div>
      <div class="actions">
        <button type="submit" class="primary-btn">查询聊天文件</button>
      </div>
    </form>

    <div class="summary-row">
      <div class="summary-card">
        <strong id="chatFileCount">0</strong>
        <span>聊天文件结果数</span>
      </div>
    </div>

    <div id="chatFileSelectedCard" class="selected-card" style="margin-top: 14px;">
      <h3>未选择聊天文件</h3>
      <p>从下方列表选择一条文件记录后，这里会显示文件指纹、落盘路径和消息绑定信息。</p>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>文件</th>
            <th>上传者</th>
            <th>会话</th>
            <th>绑定消息</th>
            <th>本地状态</th>
            <th>创建时间</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody id="chatFilesBody">
          <tr><td colspan="7" class="muted">正在等待首次加载。</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</section>
)HTML";

    const std::string script = R"JS((function () {
  const shell = window.__adminShell;
  const state = {
    avatars: [],
    chatFiles: [],
    selectedFileId: null
  };

  const avatarsBody = document.getElementById("avatarsBody");
  const chatFilesBody = document.getElementById("chatFilesBody");

  function getSelectedChatFile() {
    return state.chatFiles.find(function (file) {
      return String(file.file_id) === String(state.selectedFileId);
    }) || null;
  }

  function renderAvatarCount() {
    document.getElementById("avatarCount").textContent = String(state.avatars.length);
  }

  function renderChatFileCount() {
    document.getElementById("chatFileCount").textContent = String(state.chatFiles.length);
  }

  function renderAvatars() {
    renderAvatarCount();
    if (!state.avatars.length) {
      avatarsBody.innerHTML = "<tr><td colspan='6' class='muted'>没有匹配的头像记录。</td></tr>";
      return;
    }
    avatarsBody.innerHTML = state.avatars.map(function (user) {
      const preview = user.preview_url
        ? ("<a class='text-link' href='" + shell.escapeHtml(user.preview_url) + "' target='_blank' rel='noreferrer'><img class='thumb' src='" + shell.escapeHtml(user.preview_url) + "' alt='avatar preview'></a>")
        : "<div class='thumb-fallback'>无图</div>";
      const fileStatusClass = user.avatar_file_exists ? "online" : "offline";
      const fileStatusLabel = user.avatar_file_exists ? "已落盘" : "未落盘";
      return (
        "<tr>" +
          "<td><div class='user-main'><strong>" + shell.escapeHtml(user.nickname || user.username || "-") + "</strong><span class='muted'>@" + shell.escapeHtml(user.username || "-") + " / user_id " + shell.escapeHtml(user.user_id || "-") + " / #" + shell.escapeHtml(user.numeric_id || "-") + "</span></div></td>" +
          "<td>" + preview + "</td>" +
          "<td class='mono'>" + shell.escapeHtml(user.profile_avatar_url || "-") + "</td>" +
          "<td><div class='user-main'><span class='tag " + fileStatusClass + "'>" + shell.escapeHtml(fileStatusLabel) + "</span><span class='muted mono'>" + shell.escapeHtml(user.avatar_filename || "-") + "</span></div></td>" +
          "<td>" + shell.escapeHtml(String(user.avatar_size_bytes || 0)) + "</td>" +
          "<td>" + shell.escapeHtml(user.avatar_modified_at || "-") + "</td>" +
        "</tr>"
      );
    }).join("");
  }

  function renderSelectedChatFile() {
    const card = document.getElementById("chatFileSelectedCard");
    const file = getSelectedChatFile();
    if (!file) {
      card.innerHTML = "<h3>未选择聊天文件</h3><p>从下方列表选择一条文件记录后，这里会显示文件指纹、落盘路径和消息绑定信息。</p>";
      return;
    }
    card.innerHTML =
      "<h3>" + shell.escapeHtml(file.original_name || file.stored_name || file.file_id || "-") + "</h3>" +
      "<div class='detail-list'>" +
        "<p class='muted mono'>file_id: " + shell.escapeHtml(file.file_id || "-") + "</p>" +
        "<p>上传者: <strong>" + shell.escapeHtml(file.uploader_nickname || file.uploader_username || "-") + "</strong> / @" + shell.escapeHtml(file.uploader_username || "-") + " / user_id " + shell.escapeHtml(file.uploader_user_id || "-") + "</p>" +
        "<p>会话: <strong>" + shell.escapeHtml(file.conversation_id || "-") + "</strong>，大小: <strong>" + shell.escapeHtml(String(file.size_bytes || 0)) + "</strong> B，类型: <strong>" + shell.escapeHtml(file.content_type || "-") + "</strong></p>" +
        "<p>绑定消息: <strong>" + shell.escapeHtml(file.bound_message_id || "-") + "</strong>，本地文件: <strong>" + shell.escapeHtml(file.safe_relative_path || file.stored_relative_path || "-") + "</strong></p>" +
        "<p class='mono'>sha256: " + shell.escapeHtml(file.sha256 || "-") + "</p>" +
      "</div>";
  }

  function renderChatFiles() {
    renderChatFileCount();
    renderSelectedChatFile();
    if (!state.chatFiles.length) {
      chatFilesBody.innerHTML = "<tr><td colspan='7' class='muted'>没有匹配的聊天文件记录。</td></tr>";
      return;
    }
    chatFilesBody.innerHTML = state.chatFiles.map(function (file) {
      const selected = String(file.file_id) === String(state.selectedFileId);
      const localClass = file.file_exists ? "online" : "offline";
      const localLabel = file.file_exists ? "文件存在" : "文件缺失";
      const attachedLabel = file.attached ? (file.bound_message_id || "已绑定") : "未绑定";
      const downloadLink = file.download_url
        ? ("<a class='text-link' href='" + shell.escapeHtml(file.download_url) + "'>后台下载</a>")
        : "-";
      return (
        "<tr class='" + (selected ? "selected" : "") + "' data-file-id='" + shell.escapeHtml(file.file_id) + "'>" +
          "<td><div class='user-main'><strong>" + shell.escapeHtml(file.original_name || file.stored_name || "-") + "</strong><span class='muted mono'>" + shell.escapeHtml(file.file_id || "-") + "</span></div></td>" +
          "<td><div class='user-main'><strong>" + shell.escapeHtml(file.uploader_nickname || file.uploader_username || "-") + "</strong><span class='muted'>@" + shell.escapeHtml(file.uploader_username || "-") + " / user_id " + shell.escapeHtml(file.uploader_user_id || "-") + "</span></div></td>" +
          "<td class='mono'>" + shell.escapeHtml(file.conversation_id || "-") + "</td>" +
          "<td class='mono'>" + shell.escapeHtml(attachedLabel) + "</td>" +
          "<td><span class='tag " + localClass + "'>" + shell.escapeHtml(localLabel) + "</span></td>" +
          "<td>" + shell.escapeHtml(file.created_at || "-") + "</td>" +
          "<td>" + downloadLink + "</td>" +
        "</tr>"
      );
    }).join("");

    Array.prototype.forEach.call(chatFilesBody.querySelectorAll("tr[data-file-id]"), function (row) {
      row.addEventListener("click", function () {
        state.selectedFileId = row.getAttribute("data-file-id");
        renderChatFiles();
      });
    });
  }

  async function loadAvatars(showFlash) {
    const params = new URLSearchParams();
    const keyword = document.getElementById("avatarKeywordInput").value.trim();
    if (keyword) {
      params.set("keyword", keyword);
    }
    params.set("limit", document.getElementById("avatarLimitInput").value);
    params.set("include_disabled", document.getElementById("avatarIncludeDisabledInput").checked ? "1" : "0");
    const payload = await shell.api("/admin/api/files/avatars?" + params.toString());
    state.avatars = Array.isArray(payload.avatars) ? payload.avatars : [];
    renderAvatars();
    if (showFlash) {
      shell.setFlash("头像元数据已刷新。", "info");
    }
  }

  async function loadChatFiles(showFlash) {
    const params = new URLSearchParams();
    const keyword = document.getElementById("chatFileKeywordInput").value.trim();
    const conversationId = document.getElementById("chatFileConversationIdInput").value.trim();
    const uploaderUserId = document.getElementById("chatFileUploaderUserIdInput").value.trim();
    const fileId = document.getElementById("chatFileIdInput").value.trim();
    if (keyword) {
      params.set("keyword", keyword);
    }
    if (conversationId) {
      params.set("conversation_id", conversationId);
    }
    if (uploaderUserId) {
      params.set("uploader_user_id", uploaderUserId);
    }
    if (fileId) {
      params.set("file_id", fileId);
    }
    params.set("limit", document.getElementById("chatFileLimitInput").value);

    const payload = await shell.api("/admin/api/files/chat?" + params.toString());
    state.chatFiles = Array.isArray(payload.chat_files) ? payload.chat_files : [];
    if (!state.chatFiles.some(function (file) { return String(file.file_id) === String(state.selectedFileId); })) {
      state.selectedFileId = state.chatFiles.length ? String(state.chatFiles[0].file_id) : null;
    }
    renderChatFiles();
    if (showFlash) {
      shell.setFlash("聊天文件元数据已刷新。", "info");
    }
  }

  document.getElementById("avatarSearchForm").addEventListener("submit", function (event) {
    event.preventDefault();
    loadAvatars(true).catch(function (error) {
      shell.setFlash(error.message, "error");
    });
  });

  document.getElementById("refreshAvatarsBtn").addEventListener("click", function () {
    loadAvatars(true).catch(function (error) {
      shell.setFlash(error.message, "error");
    });
  });

  document.getElementById("chatFileSearchForm").addEventListener("submit", function (event) {
    event.preventDefault();
    loadChatFiles(true).catch(function (error) {
      shell.setFlash(error.message, "error");
    });
  });

  document.getElementById("refreshChatFilesBtn").addEventListener("click", function () {
    loadChatFiles(true).catch(function (error) {
      shell.setFlash(error.message, "error");
    });
  });

  shell.loadSession()
    .then(function () {
      return Promise.all([loadAvatars(false), loadChatFiles(false)]);
    })
    .catch(function (error) {
      shell.setFlash(error.message, "error");
    });
}());)JS";

    return build_admin_shell(admin_page_kind::files, body, script);
}

} // namespace server
} // namespace qt_server
