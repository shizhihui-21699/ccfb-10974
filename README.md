# apk-audit — 无第三方依赖的 Android APK 静态安全审计工具

直接解析 APK 内的二进制 `AndroidManifest.xml`（AXML 格式），**不依赖 aapt / aapt2 /
jadx**；同时审计 `network_security_config` 与 APK 签名方案 v1/v2/v3，对 intent-filter
暴露的组件给出分级风险说明。仅使用 Python 标准库；签名密码学验证调用系统 `openssl` CLI。

## 能力范围

| 模块 | 检查内容 |
| --- | --- |
| AXML 解析 | 自有二进制 XML 解析器（string pool / resource map / 命名空间 / 类型化属性），支持 UTF-8/UTF-16 池、布尔/整数/引用等类型 |
| 清单基线 | `debuggable`、`allowBackup`、`testOnly`、`usesCleartextTraffic`、`networkSecurityConfig`、SDK 版本 |
| 组件暴露 | activity / activity-alias / service / receiver / provider 的显式与隐式导出、intent-filter（含 deep link）、保护权限、`grantUriPermissions` |
| 权限 | 敏感运行时权限清单、自定义权限的 `protectionLevel` 强度 |
| 网络安全配置 | 明文流量 `cleartextTrafficPermitted`、用户/系统 CA 信任、证书固定 pin-set |
| 签名 v1 (JAR) | MANIFEST.MF / .SF / PKCS#7 结构、逐条目摘要、SF 对清单摘要、PKCS#7 验签、SHA-1 弱哈希 |
| 签名 v2/v3 | APK Signing Block 解析（block id `0x7109871a` / `0xf05368c0`）、分块内容摘要（1 MiB，前缀 `0xa5`/`0x5a`）、openssl 密码学验签、v3 minSdk/maxSdk |

## 风险分级

| 级别 | 含义 | 典型规则 |
| --- | --- | --- |
| **CRITICAL 严重** | 可直接判定样本被篡改 / 完全无签名 | `SIG-*-VERIFY-FAIL`、`SIG-NONE` |
| **HIGH 高危** | 显著降低攻击门槛，少量或零交互可利用 | `debuggable`、无保护导出 service/receiver/provider、VIEW deep link、信任用户 CA、仅 v1 签名 |
| **MEDIUM 中危** | 扩大攻击面或违反加固基线，利用需前置条件 | `allowBackup`、明文流量、normal 级自定义权限、SHA-1 弱哈希 |
| **INFO 信息** | 信息收集与最佳实践 | 敏感权限申请、启动器导出、缺 pin-set、旧 targetSdk 的默认值提示 |

综合评分 0–100（严重 25 / 高危 12 / 中危 5 / 信息 1，封顶 100），并映射为
通过 / 低危 / 中危 / 高危四档。

## 使用

```bash
# 文本报告（中文，带颜色）
python3 -I apk_auditor/cli.py samples/apks/good-app.apk

# 机器可读 JSON
python3 -I apk_auditor/cli.py samples/apks/insecure-app.apk --json

# 一次审计多个并落盘
python3 -I apk_auditor/cli.py samples/apks/*.apk --output reports/ --no-color
```

退出码：`0` 仅 INFO/无风险；`1` 存在中危及以上（便于接入 CI 卡口）；`2` 用法或文件错误。

## 生成测试 APK

```bash
python3 -I samples/generator/build_samples.py
```

产出四个样本到 `samples/apks/`：

- `good-app.apk` — 加固基线，v1+v2+v3 签名齐全且验签通过（低危，仅启动器 INFO）
- `insecure-app.apk` — debuggable / testOnly / 明文 / 用户 CA / 四类导出组件 / 弱自定义权限（高危）
- `legacy-v1-sha1-app.apk` — 仅 v1 + SHA-1，旧 targetSdk（高危签名缺失 + 弱哈希）
- `tampered-app.apk` — 在已签名包上翻转未压缩条目字节，三个方案均判 CRITICAL

测试 APK 的 v1/v2/v3 签名由 `samples/generator/` 从零实现（RSA-2048 +
RSASSA-PKCS1-v1_5/SHA-256），无需 Android SDK 或 apksigner。

## 测试

```bash
python3 -I -m unittest discover -s tests -v
```

26 个用例覆盖 AXML 往返、类型解码、分块摘要、v1/v2/v3 验签、篡改检测、各风险规则
与四个样本的端到端审计。

## 目录结构

```
apk_auditor/
  binary.py             小端/大端二进制读取原语
  axml.py               AXML 解析器（含框架属性资源 ID 映射）
  axml_writer.py        AXML 编码器（测试样本与往返测试用）
  signing.py            v1/v2/v3 签名检测、摘要与 openssl 验签
  manifest_analysis.py  清单/网络配置分析与风险分级
  audit.py              顶层编排与结果模型
  report.py             中文文本 / JSON 报告
  cli.py                命令行入口
samples/generator/      测试 APK 与签名构造器
tests/                  单元与端到端测试
```

## 安全说明

工具仅做静态分析，不执行 APK 内任何代码。解析第三方样本时建议沿用 `-I`（隔离模式）
运行，避免样本目录中的同名模块污染导入路径。
