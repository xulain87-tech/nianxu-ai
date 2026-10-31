# 念绪 AI 管理后台

Render 配置：
- Runtime: Node
- Build Command: `npm install`
- Start Command: `npm start`

Environment Variables:
- `ADMIN_ID`: 管理员登录凭据（请设置为你自己的秘密密码）
- `DATA_DIR`: `/data`（仅当挂载持久化磁盘到 `/data` 时设置；否则可留空）

注意：部署前请检查 index.html 的登录/API 接入是否匹配你现有站点。该基础版本支持管理员认证与公告，不含用户封禁/聊天记录管理。不要将管理员凭据提交到 GitHub。
