# 念绪 AI 2.0 Pro（PWA + 管理后台）

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
- 统一设置中心：接口、版本、功能开关、服务状态与权限说明
- 低延迟优先的接口轮询：单个接口 18 秒独立超时，失败自动切换
- AI 生图入口：通过公共图片生成服务生成并回显图片
- 预设 5 个公益/免费额度接口：Pollinations 公共入口、OpenRouter Free、Groq Free、Hugging Face Inference、Cerebras Free Trial；除公共入口可能直接可用外，其余需要用户自行申请对应 Key，具体额度以服务商当前规则为准
- PWA：支持手机浏览器“添加到主屏幕”安装

## 安全/限制
- 不包含或代提供第三方 API Key；请勿将密钥提交到公开仓库。当前接口配置默认保存在浏览器本地，适合个人测试。多人公共部署应进一步迁移到后端代理并加速率限制。
- ID-only 登录意味着用户可冒用其他普通 ID；不适合存放敏感内容。管理员权限仍由后端环境变量校验。
- Render 免费实例休眠/临时文件系统限制可能影响在线状态和数据持久化；持久数据请配置磁盘。
