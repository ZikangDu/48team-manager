# 48 Team Manager

本机 macOS 部署与使用见 [本地部署说明](docs/local-deployment.md)，服务地址为 `http://127.0.0.1:8018`，使用 `./scripts/local-service.sh` 管理。

自用的 ChatGPT Team 运营控制台：管理多个团队的母号 / 子号、查看官方额度、重新授权、安全轮转，并与 Sub2API、iCloud HME 联动。不是 SaaS、CRM 或质保平台。

技术栈：Python、FastAPI、SQLite、Jinja2 + 原生 JS、APScheduler、Playwright。单容器部署。

## 快速开始

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python -m uvicorn app.main:app --reload --port 8008
```

打开 `http://127.0.0.1:8008`，账号密码见 `.env`。

## 文档

- [产品与业务规则](docs/PRODUCT.md)
- [架构、配置与基本检查](docs/ARCHITECTURE.md)
- [部署与运维](docs/RUNBOOK.md)
- [HME 联动规则](docs/hme-linkage.md)
- [邀请席位接口约定](docs/contracts/openai-invite.md)
- [注册插件说明](extensions/chatgpt-signup/README.md)
- [导入已有授权凭据](docs/credential-import.md)
- [账号登录与安全](docs/assisted-login.md)
- [更新日志](CHANGELOG.md)
