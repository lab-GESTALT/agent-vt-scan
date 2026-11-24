# vt-cli 命令矩阵

安装：`go install github.com/VirusTotal/vt-cli/vt@latest`（产物在 `%USERPROFILE%\go\bin\vt.exe`）。

鉴权：`vt init` 交互式写入配置，或直接设 `VTCLI_APIKEY`。脚本里永远用环境变量，不写进命令行参数（会进 shell 历史）。

## 常用

| 目的 | 命令 |
| --- | --- |
| 按哈希查文件 | `vt file <sha256> -i last_analysis_stats,signature_info,meaningful_name` |
| 上传文件 | `vt scan file <path>` |
| 查分析进度 | `vt analysis <id> -i stats,status` |
| 查域名 | `vt domain <domain> -i last_analysis_stats` |
| 查 IP | `vt ip <ip> -i last_analysis_stats` |
| 查 URL | `vt url <url> -i last_analysis_stats` |
| JSON 输出 | 全部命令加 `-j` 或 `--format json` |

## 退出码

- `0` 成功
- 非 `0` 分两类：请求本身失败（网络、鉴权）与业务无结果（404）。脚本里必须区分，不要把 404 当 clean。

## REST 等价物

没有 vt-cli 时用 REST，字段一致：

```
GET  https://www.virustotal.com/api/v3/files/<sha256>
POST https://www.virustotal.com/api/v3/files        (multipart: file)
GET  https://www.virustotal.com/api/v3/analyses/<id>
Header: x-apikey: <key>
```

免费档限额：每分钟 4 次、每天 500 次。批量场景要加本地缓存（按哈希存结果，TTL 24 小时）。

## 坑

- 上传大文件走 `/files/upload_url` 拿专用地址，不要直接 POST 到 `/files`。
- 分析不是同步的，上传后立刻查 stats 会拿到 0，需要轮询。
- `last_analysis_stats.undetected` 的分母随引擎数量变化，别把绝对值当比例看。
