"""apk_audit —— 纯标准库 Android APK 静态审计工具。

不依赖 aapt / androguard / cryptography，直接解析 APK 内的二进制
AndroidManifest（AXML）、network_security_config 与 v1/v2/v3 签名块。
"""

__version__ = "1.0.0"
