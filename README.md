# 念绪 AI 2.0 Pro（PWA + 管理后台）

## Render 部署
- Runtime: Node
- Build Command: `npm install`
- Start Command: `npm start`
- Environment: `ADMIN_ID` 设置为管理员专属 ID/口令；`NODE_ENV=production`；需要启用智谱时设置 `ZHIPU_API_KEY`
- 可选持久化：挂载磁盘到 `/data` 并设置 `DATA_DIR=/data`

## 功能
- ID 登录（无需普通用户密码）；管理员 ID 由服务器环境变量 `ADMIN_ID` 验证
- 管理后台：在线用户列表、封禁/解封、公告
- 接口设置：管理员配置 OpenAI 兼容 Chat Completions API，Key 只保存在服务器端
- 背景图片/视频、头像、字体、字号、主题偏好
- 统一设置中心：接口、版本、功能开关、服务状态与权限说明
- 低延迟优先的接口轮询：单个接口 18 秒独立超时，失败自动切换
- AI 生图入口：通过公共图片生成服务生成并回显图片
- 预设 5 个公益/免费额度接口：Pollinations 公共入口、念绪AI（智谱 GLM-5.3）、Groq Free、Hugging Face Inference、Cerebras Free Trial；除公共入口可能直接可用外，其余需要用户自行申请对应 Key，具体额度以服务商当前规则为准
- PWA：支持手机浏览器“添加到主屏幕”安装

## 安全/限制
- 普通用户只请求 `/api/ai/chat`，服务器代发第三方请求；前端不接收接口地址、模型或 API Key。管理员登录后可在接口设置中查看、复制和修改原始 Key。
- 不要把真实 Key 写入 `index.html`、压缩包或公开仓库；Render 请通过 Environment 设置 `ZHIPU_API_KEY`，或管理员登录后在接口设置中录入。
- UI 使用无外部图片资源、无高耗能模糊、限制聊天 DOM 为最近 60 条并将生图尺寸限制为 768px；实际内存会受浏览器和设备影响，无法保证所有环境固定为 80MB。
- 应用层防火墙按 IP 和路由限流，包含登录防爆破、AI 请求限流、请求体限制、安全响应头和可选 `BLOCKED_IPS` 黑名单。
- Render 容器内不能直接管理 UFW/iptables；如需更强的网络层 WAF，可在 Render 前接入 Cloudflare 等反向代理。
- ID-only 登录意味着用户可冒用其他普通 ID；不适合存放敏感内容。管理员权限仍由后端环境变量校验。
- Render 免费实例休眠/临时文件系统限制可能影响在线状态和数据持久化；持久数据请配置磁盘。
