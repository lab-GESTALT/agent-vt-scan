# agent-vt-scan

给 agent 用的文件体检查询链路：一个文件进来，两个引擎给结论——本地 Kaspersky 命令行扫描，加 VirusTotal 云端情报（`vt-cli` 或 REST）。

面向的场景是「agent 自己要下载、解压、执行别人给的文件」。人类双击右键扫一下就够了，agent 没有右键，所以需要一条能被脚本调用的路。

## 为什么需要它

agent 的常规动作是 `Invoke-WebRequest`、`curl`、`git clone`、解压附件。这四步里没有一步会触发杀毒软件。宿主机的实时防护能兜住执行，但兜不住「先看清楚再决定要不要执行」。

所以这里提供的是**执行前的确认步骤**，不是替代杀毒软件。

## 两个引擎，各管一段

| 引擎 | 能回答的问题 | 代价 |
| --- | --- | --- |
| Kaspersky CLI | 这台机器上，这个文件现在有没有事 | 本地、离线、几十毫秒到几秒 |
| VirusTotal | 全世界有没有人见过它，各家引擎怎么说 | 联网、有配额、需要哈希 |

先查 VT（按哈希，不传文件），再本地扫。两边都干净才继续；任一边报警就停手问人。

## 安装

```powershell
# vt-cli
go install github.com/VirusTotal/vt-cli/vt@latest

# 密钥（不要写进仓库）
$env:VTCLI_APIKEY = (Get-Content "$HOME\.vt\api.key" -Raw).Trim()
```

Kaspersky 不需要安装，只需要知道 `avp.com` 在哪：

```powershell
Get-ChildItem 'C:\Program Files (x86)\Kaspersky Lab' -Recurse -Filter avp.com | Select-Object -First 1 -ExpandProperty FullName
```

## 用法

```powershell
# 只要结论，输出 JSON
.\scripts\scan.ps1 -Path .\download.zip

# 本地扫描 + VT 查询，未知文件不上传
.\scripts\scan.ps1 -Path .\download.zip -Engine both

# 哈希在 VT 上没有记录时，显式允许上传（会暴露文件内容，慎用）
.\scripts\scan.ps1 -Path .\download.zip -Engine both -Upload
```

输出契约：`verdict` 取值 `clean` / `suspicious` / `malicious` / `unknown` / `error`，附两个引擎的原始计数。

## 安全边界

- API 密钥只从环境变量或本地密钥文件读，脚本里没有硬编码，仓库里也没有。
- 默认**不上传文件**，只算哈希查库。上传必须显式加 `-Upload`。
- VT 的结论是情报，不是判决。`malicious` 计数为 1 也可能是误报，为 0 也可能还没人见过。

## 目录

```
SKILL.md                  agent 执行说明（pstack 格式）
scripts/scan.ps1          双引擎入口
references/cli.md         vt-cli 命令矩阵与退出码
references/kaspersky.md   avp.com 的 agent 调用方式与报告解析
references/policy.md      判定与处置策略
```

## 关键词

virus scanning for agents, vt-cli, VirusTotal API, Kaspersky avp.com, agent security, malware hash lookup, automated file triage, PowerShell.

## License

MIT
