# Chat File Transfer Migration

新增表：

```sql
CREATE TABLE IF NOT EXISTS chat_files (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    file_uuid VARCHAR(64) NOT NULL,
    conversation_id BIGINT UNSIGNED NOT NULL,
    conversation_uuid VARCHAR(64) NOT NULL,
    uploader_user_id BIGINT UNSIGNED NOT NULL,
    original_name VARCHAR(255) NOT NULL,
    stored_name VARCHAR(255) NOT NULL,
    stored_relative_path VARCHAR(512) NOT NULL,
    size_bytes BIGINT UNSIGNED NOT NULL,
    content_type VARCHAR(128) NOT NULL,
    sha256 CHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    bound_message_uuid VARCHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attached_at DATETIME NULL DEFAULT NULL,
    UNIQUE KEY uk_chat_files_uuid (file_uuid),
    KEY idx_chat_files_conversation (conversation_id, created_at),
    KEY idx_chat_files_download (file_uuid, conversation_id, uploader_user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

约定：

- `messages.message_type = 1` 表示文本消息
- `messages.message_type = 2` 表示文件消息
- 文件消息的 `messages.content` 为 JSON，包含：
  - `file_id`
  - `original_name`
  - `stored_name`
  - `size_bytes`
  - `content_type`
  - `sha256`

新增 HTTP 接口：

- `POST /upload/chat-file`
- `GET /download/chat-file/{file_id}`
- `HEAD /download/chat-file/{file_id}`

登录响应新增字段：

- `chat_file_upload_token`
- `chat_file_upload_token_expires_at`
- `chat_file_upload_token_type`
