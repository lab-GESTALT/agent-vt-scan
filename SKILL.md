---
name: vt-scan
description: 下载、解压、执行第三方文件之前的体检链路。用本地 Kaspersky 命令行扫一遍，再用 VirusTotal 按哈希查云端情报；两端都干净才放行。适用于 agent 自己拉取附件、二进制、压缩包、脚本的场景。
allowed-tools:
  - Bash
  - Read
---

# vt-scan

## 什么时候用

- agent 自己 `curl` / `Invoke-WebRequest` / `git clone` 下来一个文件，准备执行或解压
- 用户发来附件，准备打开、导入、反编译
- 准备把某个二进制加入 PATH，或写进开机启动

不适用：纯文本你自己写的文件；已经在源仓库里被 CI 校验过的依赖。

## 硬规则

1. **密钥不进仓库、不进日志、不进回复。** 只从 `VTCLI_APIKEY` 环境变量或本地密钥文件读。
2. **默认不上传文件。** 先算哈希查库；查不到时，只有明确知道「这个文件不含隐私」才加 `-Upload`，否则报 `unknown` 并交给人判断。
3. **两端都干净才放行。** Kaspersky 报 `Total detected > 0` 或 VT 的 `malicious >= 1`，一律停手，把证据摆给用户，不要自作主张删文件。
4. **结论分级，不给单一布尔值。** `clean` / `suspicious` / `malicious` / `unknown` / `error` 五档，附原始计数。

## 流程

1. 取文件绝对路径，确认存在、可读、大小。
2. 算 SHA-256。
3. 查 VT：`vt file <sha256> --include=last_analysis_stats,meaningful_name,signature_info`。命中即得各引擎票数。
4. 未命中：默认停在这里报 `unknown`；如用户同意上传，`vt scan file <path>` 后再按返回的分析 ID 轮询一次。
5. 本地扫：调用 `avp.com SCAN <path> /R:<report> /RA:<report>`，解析报告里的 `Total detected`、`Total OK`、`Errors`。
6. 合并判定，输出 JSON，向用户报一句话结论加证据。

## 判定表

| VT malicious | Kaspersky detected | verdict |
| --- | --- | --- |
| 0 | 0 | clean |
| 1-2 | 0 | suspicious |
| >= 3 或知名家族命中 | 任意 | malicious |
| 0 | > 0 | malicious（本地定论优先） |
| 未命中且未上传 | 0 | unknown |

`suspicious` 不等于放行：可以继续读取和分析，但不要执行。

## 调用

```powershell
.\scripts\scan.ps1 -Path <file> [-Engine vt|kav|both] [-Upload]
```

输出示例：

```json
{"path":"...","sha256":"...","verdict":"clean","vt":{"found":true,"malicious":0,"suspicious":0,"total":72,"name":"..."},"kav":{"detected":0,"ok":3,"errors":0}}
```

## 失败模式

- `avp.com` 找不到：说明卡巴版本目录变了，按 `references/kaspersky.md` 的定位命令重新取路径，不要跳过本地扫描就报 clean。
- VT 返回 401：密钥没设或过期，报 `error`，不要降级成 clean。
- VT 返回 429：配额打满。报 `error` 并说明「只完成了本地扫描」，不要伪造云端结论。
- 报告文件被占用：换一个临时目录，别复用同一个文件名。
