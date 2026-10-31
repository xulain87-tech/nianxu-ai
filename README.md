# 念绪 AI 1.0（PWA + 管理后台）

## Render 部署
- Runtime: Node
- Build Command: `npm install`
- Start Command: `npm start`
- Environment: `ADMIN_ID` 设置为管理员专属 ID/口令；`NODE_ENV=production`
- 可选持久化：挂载磁盘到 `/data` 并设置 `DATA_DIR=/data`

## 功能
- ID 登录（无需普通用户密码）；管理员 ID 由服务器环境变量 `ADMIN_ID` 验证
- 管理后台：在线用户列表、封禁/解封、公告
- 接口设置：支持 OpenAI 兼容 Chat Completions API，用户需配置自己合法取得的 API Key
- 背景图片/视频、头像、字体、字号、主题偏好
- PWA：支持手机浏览器“添加到主屏幕”安装

## 安全/限制
- 不包含或代提供第三方 API Key；请勿将密钥提交到公开仓库。当前接口配置默认保存在浏览器本地，适合个人测试。多人公共部署应进一步迁移到后端代理并加速率限制。
- ID-only 登录意味着用户可冒用其他普通 ID；不适合存放敏感内容。管理员权限仍由后端环境变量校验。
- Render 免费实例休眠/临时文件系统限制可能影响在线状态和数据持久化；持久数据请配置磁盘。
