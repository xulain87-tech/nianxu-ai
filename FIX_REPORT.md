# ASTRION 1.2.0 修复与验收报告

## 本轮修复（对应 1.1.9 用户反馈）

### 1. AI 一直显示"输入中"
- 根因 A（主因）：主聊天输入框的 Enter 键处理缺少中文输入法组合态检查（`isComposing`/`keyCode 229`）。用拼音输入法每按一次回车确认候选词，都会被当成"发送"，消息区不断出现"输入中……"的气泡，看起来就是"AI 一直在输入中"。创新AI 面板的新代码有该检查而主聊天旧代码没有，属于新旧代码混合导致的缺陷。现已补齐检查。
- 根因 B：`send()` 后半段（结果渲染、setBusy(false)）不在异常保护内，一旦中间抛错，"输入中"气泡永久挂起、发送按钮永久禁用。现已全程 try/catch/finally 兜底：任何情况下"输入中"都会被解除、busy 状态必然复位。
- 优化：请求超时从 20/30/55 秒放宽到 35/45/60 秒，避免服务器冷启动时过早中断。

### 2. 弹窗 ❌ 点了退不了
- 根因 A：控制台/公告/转人工等弹窗的打开函数（forceShow、openApiConfigPanel 等）写入内联 `display:flex; z-index; pointer-events` 样式，而关闭逻辑只移除 `.show` 类——内联样式优先级更高，弹窗永远关不掉。手机上弹窗全屏铺满、点不到背景，用户被完全卡住。
- 修复：新增统一关闭函数 `closeLayer()`（移除 show 类 + 清理全部相关内联样式），所有关闭入口（✕ 按钮、data-close、data-extra-close、点背景、Esc 键）全部改走该函数；打开函数不再写任何内联样式；打开弹窗时自动收起移动端侧栏，避免侧栏高 z-index 盖住弹窗。
- Esc 键现在同时能关闭接口配置面板与设置面板。

### 3. 左侧栏太小
- 桌面侧栏从 260px 加宽到 300px（≥1500px 宽屏 330px）；移动端抽屉统一为 min(84vw, 340px)，清除了原先 300px/330px 两套互相矛盾的规则。

### 4. 设置 / 公告 / 控制台 UI 配色
- 新增全局主题层 `nx-theme-unify`，将登录页同款"粉紫蓝 Aurora"渐变（#ff6b9d → #c084fc → #60a5fa）与深色毛玻璃卡片统一应用到：设置弹窗、公告中心、管理控制台、转人工工单、外观设置、AI 生图、接口配置面板；主按钮、输入框聚焦光圈、勾选框、滚动条同步换色。

### 5. 新旧代码混合清理
- 修正接口面板自相矛盾的旧文案："首槽固定为智谱 GLM-4.7-Flash" → "首槽固定为 Groq openai/gpt-oss-120b"（与后端实际一致）。
- 修复 nx-dola-home 的坏 DOM 插入（模板为空时 insertBefore(null) 抛 TypeError）。
- 移除建议按钮的双重绑定（旧 onclick + 新 capture 委托会连发两次）。
- Service Worker 缓存版本升级为 astrion-shell-v1.2.0，部署后旧缓存自动失效。
- 页面版本号全面更新为 1.2.0。

## 验收结果
- `npm test` 通过（认证、五槽配置、密钥隔离、HTTPS 校验、竞速回退、公告、注销等）。
- `node --check server.js / sw.js / tests/smoke.js` 通过；19 段内联 JavaScript 语法全部通过。
- 本机实跑服务器：页面、sw.js、logo、manifest 全部 200；登录接口正常；关键修复标记（closeLayer / nx-theme-unify / isComposing / 300px 侧栏 / 新首槽文案）全部在交付页面中确认存在。
- 未使用真实 Groq Key，未调用真实 AI 服务。

## 部署提醒
- 部署平台私密环境变量仍需配置 `ADMIN_ID`、`ADMIN_PASSWORD`、`GROQ_API_KEY`（生图另配 `ZHIPU_API_KEY`），`DATA_DIR` 指向持久化磁盘。
- 更新部署后建议用户强刷一次页面；Service Worker 会自动清理旧缓存。
