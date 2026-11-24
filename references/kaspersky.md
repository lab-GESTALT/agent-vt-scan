# Kaspersky 的 agent 通道

人类用右键「扫描」，agent 没有右键。可脚本调的入口是 `avp.com`。

## 定位

```powershell
Get-ChildItem 'C:\Program Files (x86)\Kaspersky Lab' -Recurse -Filter avp.com |
  Select-Object -First 1 -ExpandProperty FullName
```

版本目录会变（如 `Kaspersky 21.27`），所以每次动态定位，不要写死。

## 扫描并出报告

```powershell
$avp = 'C:\Program Files (x86)\Kaspersky Lab\Kaspersky 21.27\avp.com'
$rep = Join-Path $env:TEMP ("kav-" + [guid]::NewGuid().ToString('N') + '.txt')
& $avp SCAN "<目标路径>" /R:"$rep" /RA:"$rep"
```

`/R` 写报告，`/RA` 追加；两个都给，避免第二次调用覆盖。报告是分号开头的键值对，末尾有 Statistics 段：

```
; Processed objects:  2
; Total OK:           2
; Total detected:     0
; Suspicions:         0
; Errors:             0
```

## 判读

- `Total detected > 0` 就是有命中，看报告正文里 `Detected` 那几行拿家族名。
- `Errors > 0` 不代表干净，可能是权限或路径不可读，要如实上报。
- 退出码 `0` 表示任务完成，不代表无威胁；判定必须读报告，别信退出码。

## 坑

- 目录末尾的分隔符会影响递归行为，传文件路径最稳。
- 报告文件被占用会静默失败，每次用新文件名。
- 首次扫描大目录可能要几十秒，脚本要给足超时，不要 3 秒就判死。
- 隔离区操作（`/QUARANTINE`）属于破坏性动作，默认不加，除非用户明确要求。
