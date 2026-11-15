# apk_audit — 纯 Python APK 静态审计工具

面向安全组第三方 APK 评审场景，**不依赖 aapt / apksigner / androguard**，
仅用 Python 标准库直接解析 APK 内部结构，输出导出组件、权限、应用标志、
网络安全配置与 v1/v2/v3 签名方案的审计结论和风险分级。

## 能力一览

| 维度 | 检查内容 |
|------|----------|
| 二进制 Manifest | 自写 AXML 解析器，支持 UTF-8/UTF-16 字符串池、命名空间、全部 typed value |
| 应用标志 | `debuggable`、`allowBackup`、`usesCleartextTraffic`、`testOnly` 等 |
| 组件导出面 | activity/service/receiver/provider/activity-alias，含历史默认导出判定 |
| intent-filter | action/category/scheme/host/mimeType，并给出针对性风险说明 |
| 权限 | uses-permission、运行时危险权限、自定义权限 protectionLevel、sharedUserId |
| 网络安全配置 | 明文流量开关、base/debug/domain 各级是否信任用户 CA、证书固定 |
| 签名方案 | v1(JAR) 摘要与 PKCS#7 验证、v2/v3 签名块解析与整包内容摘要复算 |
| 篡改检测 | v1 条目摘要、v2/v3 分块摘要与实际 APK 内容逐字节比对 |

## 目录结构

```
apk_audit/
  axml.py        二进制 AXML 解析器（ResourceTypes.h 布局）
  apkfile.py     ZIP/中央目录手动解析 + APK Signing Block 定位
  manifest.py    Manifest 结构化模型与导出判定
  netconfig.py   network_security_config 分析
  signatures.py  v1 JAR 签名 + v2/v3 签名块解析与摘要校验
  rules.py       风险规则引擎、分级与评分
  auditor.py     编排，产出 AuditResult
  report.py      终端彩色报告
  cli.py         命令行入口
run_audit.py     隔离模式（python -I）入口
tests/
  axmlwriter.py      AXML 二进制编码器（解析器的逆操作，造夹具用）
  apksigner_lite.py  最小 ZIP 写入器 + v1/v2/v3 签名（openssl CLI）
  build_fixtures.py  生成 4 个不同风险画像的测试 APK
  test_audit.py      16 项单元测试
```

## 使用

审计单个或多个 APK，也可直接传目录（递归找 `.apk`）：

```bash
python3 -I run_audit.py /path/to/app.apk
python3 -I run_audit.py /path/to/apk_dir --no-color
python3 -I run_audit.py app.apk --json report.json
python3 -I run_audit.py app.apk --fail-on HIGH   # CI 卡点，命中即非零退出
```

> 用 `-I` 隔离模式运行：忽略环境变量与当前目录，防止 APK 同目录下
> 被植入的 `json.py` 等模块劫持导入。

## 风险分级标准

| 级别 | 含义 | 典型规则 |
|------|------|----------|
| CRITICAL | 可直接导致设备/数据被攻破 | debuggable、无保护导出 Service/Provider、签名摘要不一致、无签名 |
| HIGH | 显著放大攻击面或削弱信任 | 明文流量、信任用户 CA、allowBackup、testOnly、核心签名方案缺失 |
| MEDIUM | 需特定条件才可利用 | 带权限保护的导出组件、运行时危险权限、debug-overrides 放开 |
| LOW | 加固/规范类问题 | 未显式 exported、弱保护自定义权限、纯启动器 Activity、sharedUserId |
| INFO | 事实记录 | 签名齐全、默认安全的网络配置 |

评分从 100 起扣（CRITICAL -40 / HIGH -15 / MEDIUM -6 / LOW -2），
按最高级别给出「不通过 / 需整改复审 / 建议整改 / 可选优化 / 通过」结论。

### 导出判定的平台规则

- `android:exported` 显式声明时以声明为准。
- targetSdk ≥ 31：含 intent-filter 却未声明 exported，安装期直接拒绝。
- targetSdk < 31：activity/service/receiver/activity-alias 含 filter 且未声明时
  **历史默认导出**；provider 在 minSdk < 17 时默认导出。
- 纯 MAIN/LAUNCHER 启动器 Activity 属预期暴露，按 LOW 提示而非高危。

## 签名方案说明

- **v1（JAR 签名）**：解析 `META-INF/MANIFEST.MF`、`.SF`、PKCS#7，逐条目复算
  摘要；PKCS#7 密码学验证调用系统 `openssl cms`（无 openssl 时降级为仅结构检查）。
- **v2/v3**：手动解析 APK Signing Block 的 length-prefixed 序列，按 AOSP 规范
  对签名块前内容做 **1MB 分块 SHA-256** 复算，与签名块内摘要比对。
- **v3.1** 是 Android 13+ 密钥轮转增强，属可选项，缺失不影响核心方案完整性判定。

## 造测试 APK

无需 Android SDK。AXML 由 `tests/axmlwriter.py` 编码，签名由
`tests/apksigner_lite.py` 配合系统 openssl 生成：

```bash
python3 -I tests/build_fixtures.py tests/fixtures
```

产出四个画像：

| APK | 画像 | 签名 | 预期评分 |
|-----|------|------|----------|
| secure-release.apk | 配置规范的正式包 | v1+v2+v3 | 98 |
| mixed-config.apk | 好坏参半，缺 v3 | v1+v2 | 61 |
| insecure-debug.apk | debuggable/明文/用户CA/暴露组件 | 仅 v1 | 0（高危） |
| unsigned-debug.apk | 未签名调试包 | 无 | 0（高危） |

## 跑测试

```bash
python3 -I tests/test_audit.py
```

覆盖 AXML 往返、布尔/整型/字符串属性、导出判定、网络配置、v1/v2/v3
校验、**篡改后摘要失效**、规则分级等 16 个用例。

## 设计约束

- 审计本体 `apk_audit/` 只用 Python 标准库；openssl 仅 v1 的 PKCS#7
  密码学验证需要，缺失时自动降级，不影响其它检查。
- 测试编码器与签名器隔离在 `tests/`，不进入审计运行路径。
- 大 APK 一次性读入内存；面向评审场景（通常 < 数百 MB）够用，如需
  流式处理可在 `apkfile.py` 基础上扩展。
