# apksec — Android APK 静态安全审计

安全组审核第三方 APK 时，通常要在 jadx / aapt / apksigner 之间来回切换。`apksec`
把“先看清单、再看网络配置、再看签名”这条固定流程做成一条命令，**纯 Python 标准库
实现，不需要 aapt / apksigner / Java / jadx**，可以直接在隔离环境或 CI 里跑。

```
python3 -m apksec audit app.apk
```

## 能力

| 能力 | 说明 |
| --- | --- |
| 二进制清单解析 | 自行解析 AXML（AndroidManifest.xml），不依赖 aapt；带完整边界与深度检查 |
| 资源解析 | 解析 `resources.arsc`，把 `@0x7f…` 还原成 `xml/…` 资源名并定位真实文件（含资源名混淆的情况） |
| 组件清点 | 列出 activity / activity-alias / service / receiver / provider，判断导出（含旧版隐式导出规则） |
| 应用级开关 | `debuggable`、`allowBackup`、`usesCleartextTraffic`、`testOnly`、`sharedUserId`、`extractNativeLibs`、`requestLegacyExternalStorage` |
| 网络安全配置 | 解析 `network_security_config`：base-config / domain-config / trust-anchors / pin-set / debug-overrides；按 targetSdk 计算平台默认值 |
| 权限 | 申请的权限、自定义权限的保护级别（normal/dangerous 视为弱保护） |
| 签名 | v1(JAR) / v2 / v3 / v3.1 完整性校验：重算内容摘要、PKCS#7 校验、CERT.SF ↔ MANIFEST.MF ↔ 归档逐层比对；调试证书、弱密钥、v1/v2 证书不一致、反剥离属性缺失 |
| intent-filter 风险说明 | 对每个暴露的 filter 给出可被谁触发、需要校验什么 |
| 风险分级 | critical / high / medium / low / info，输出评分与等级；规则可解释、可关掉 |

## 安装与运行

无第三方依赖，Python ≥ 3.10：

```bash
# 直接运行（源码目录内）
python3 -m apksec audit app.apk

# 或安装后作为命令使用
pip install -e .
apksec audit app.apk
```

### 子命令

```bash
# 完整报告（默认 text，可 --format json|markdown，-o 写文件）
python3 -m apksec audit app.apk
python3 -m apksec audit app.apk --format json -o report.json
python3 -m apksec audit app.apk --format markdown -o report.md

# CI：出现 high/critical 时以退出码 1 结束
python3 -m apksec audit app.apk --fail-on critical,high

# 只看清单结构（调试用）
python3 -m apksec dump app.apk
python3 -m apksec dump app.apk --entry res/xml/network_security_config.xml

# 只看签名（输出 JSON）
python3 -m apksec sig app.apk

# 重新生成测试语料（见下）
python3 -m apksec fixtures ./fixtures
```

退出码：`0` 正常，`1` 命中 `--fail-on` 阈值，`2` 输入无法解析。
`audit` 支持一次传入多个 APK。

## 风险分级

分级按“影响 × 可利用性”定，不看规则好不好写：

| 级别 | 判定标准 | 例子 |
| --- | --- | --- |
| critical | 任意应用即可利用，或数据直接暴露 | 导出的 ContentProvider 无权限；`debuggable=true`；未签名 / 签名校验失败 |
| high | 真实的攻击路径，利用成本低 | 导出的 activity/service/receiver 无权限；全局明文 HTTP；信任用户 CA；非启动入口的 deep link；调试证书 |
| medium | 需要特定前置条件 | 允许备份；仅 v1 签名；v1 未声明 v2/v3（可降级）；targetSdk 过低；权限为 normal/dangerous 的自定义权限 |
| low | 削弱纵深防御 | 证书过期；`extractNativeLibs=true`；minSdk 过低 |
| info | 需要知道的事实 | 有 pinning；有 debug-overrides（不可调试时）；签名方案与 minSdk 的覆盖关系 |

评分（0–100，越高越危险）由各级别权重累加（critical 25、high 12、medium 5、
low 2、info 0），同一规则重复出现按 0.5 次递增、最多 2 倍，避免“10 个导出 provider”
把分数直接顶满。等级 A–F 另外受**最严重发现**约束：有 critical 最多 D，有
high 或 medium 最多 C，有 low 最多 B——一条严重问题不会因为别处干净而被平均掉。

完整规则表见 `apksec/risk.py`（每条规则都有 `rule_id`，报告里会打印）。

## 测试语料

仓库自带 10 个自行打包的 APK（`python3 -m apksec fixtures`），覆盖正常与糟糕配置：

| 样本 | 内容 | 期望 |
| --- | --- | --- |
| `hardened.apk` | 不可调试、禁备份、禁明文、只信系统 CA、组件不导出、v1+v2+v3 | 只有 info |
| `terrible.apk` | debuggable、允许备份、全局明文、信任用户 CA、四个导出且无权限的组件、仅 v1、调试证书、targetSdk 22 | 命中 18 条规则，F |
| `missing_exported.apk` | targetSdk 33 带 filter 却未声明 `exported` | Android 12+ 安装失败 |
| `v2_only.apk` | 只有 v2，缺 v3；单个域名信任用户 CA | 中低风险 |
| `repackaged.apk` | 签名后追加 `classes2.dex` | 判定重打包 |
| `unsigned.apk` | 完全未签名 | critical |
| `ec_signed.apk` | ECDSA P-256 签名；provider 仅由未定义权限“保护” | 等价无保护 |
| `unresolved_nsc.apk` | 清单引用不存在的网络安全配置资源 | 明确报无法解析 |
| `broken_manifest.apk` | AXML chunk 长度被破坏 | 报错而非崩溃 |
| `text_manifest.apk` | 清单是明文 XML（手工改包） | 提示需要编译后的清单 |

生成器在 `tools/apkbuild/`：自行实现 AXML/ARSC 编码、ZIP 写入、X.509 证书生成、
PKCS#7 构造与 v2/v3 签名块，全部基于标准库，因此语料可离线、可复现。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

81 个用例覆盖：DER/密码学基础、AXML/ARSC 解析与畸形输入、ZIP 边界（CRC、解压上限）、
清单语义、网络配置继承、四个签名方案、规则引擎、报告与 CLI，以及一组随机变异
清单的健壮性测试。

签名结论另外用 Google 官方 `apksig` 库（JDK）交叉验证过：`hardened` / `v2_only` /
`ec_signed` / `missing_exported` 判为有效，`terrible` 仅 v1 有效，`repackaged` 报
“未在 MANIFEST 中覆盖的条目”，与 `apksec` 一致；清单元素数也与 apksig 的
二进制 XML 解析器逐项对齐（321/321）。

## 局限

- 只做静态清单 / 网络配置 / 签名层面审计，**不反编译 dex**；不会发现组件内部的
  越权逻辑、硬编码密钥或 native 漏洞。
- 不验证证书链（Android 本身也不做，签名者身份即证书本身）。
- 不处理 ZIP64、加密条目、DSA 签名（这些情况会明确报“不支持”，而不是静默跳过）。
- 签名块解析对未知算法采取“跳过并记录 warning”的策略，与 apksig 的行为一致。
