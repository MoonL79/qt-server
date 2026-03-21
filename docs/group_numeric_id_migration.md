# Group Numeric ID Migration

为群聊引入独立群号字段 `conversations.group_numeric_id`，不再复用 `conversation_uuid` 做群搜索。

建议 SQL：

```sql
ALTER TABLE conversations
ADD COLUMN group_numeric_id BIGINT UNSIGNED NULL AFTER conversation_uuid,
ADD UNIQUE KEY uk_conversations_group_numeric_id (group_numeric_id);

UPDATE conversations
SET group_numeric_id = id + 199999
WHERE type = 2
  AND group_numeric_id IS NULL;
```

约定：

- 单聊：`group_numeric_id` 保持 `NULL`
- 群聊：`group_numeric_id` 唯一，当前规则为 `id + 199999`
- 客户端群搜索优先使用 `group_numeric_id`

当前服务端行为：

- `PROFILE/CREATE_GROUP` 会返回 `group_numeric_id`
- `PROFILE/LIST_GROUPS` 支持：
  - `data.group_numeric_id`：精确查群
  - `data.keyword`：按群名模糊查
  - 两者都为空：返回空列表
