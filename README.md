# ASTRION 1.3.6

ASTRION 是一个 Node.js 单体聊天 Web 应用：账号登录、AI 聊天（五槽竞速 + 自动回退）、
联网搜索、AI 生图、创新 AI、公告、设置中心与管理控制台。

## 部署

- 要求 Node.js 18+；`npm install` 后 `npm start`。
- 必须在服务端私密环境变量配置 `ADMIN_ID`、`ADMIN_PASSWORD`（登录与管理员识别）。
- `GROQ_API_KEY` 可选：配置后主槽自动切回 Groq `openai/gpt-oss-120b`；
  未配置时主槽默认免 Key 的 Pollinations 免费接口。
- `ZHIPU_API_KEY` 可选（AI 生图）。其余见 `.env.example`。

## AI 接口

- 服务端固定 5 个槽位，聊天时多路并发竞速、谁快用谁、失败自动回退。
- 默认预填 4 个可用槽：主槽（Pollinations 免 Key / 配置 GROQ_API_KEY 后切 Groq）
  + 3 个免 Key 备用槽。全新部署开箱即用。
- 管理员在「控制台 → 接口设置」中可任意修改地址 / 模型 / Key（全站共享，Key 服务端保密，
  读取只返回是否已配置，永不回传）。

## 界面

- 主聊天界面与登录页同一设计语言：米白纸感、深绿品牌侧栏、珊瑚强调。
- 设置中心（右上角用户栏 → 设置）：个人资料 / 外观 / 个性化 / 模型 / 聊天 / 通知 / 地区 / 关于，
  个人资料面板内含切换账号与退出登录。
- 公告中心登录后自动弹出；管理员在控制台发布。

## 验证

```bash
npm test
node --check server.js
```
