超哥话探 Windows 源码
SIP · RTP 通话分析

适用于 Windows 10 / Windows 11 64 位。
源码目录：src；原生启动器：launcher；构建脚本：tools；第三方来源和校验值：third_party。

构建
使用 Python 3.11。运行 python tools/build.py 生成便携包和源码 ZIP。
Eclipse ECJ 编译器放入 .tools/ecj.jar，固定版本、下载地址和 SHA-256 见 third_party/toolchain.json。
官方 Temurin 运行环境 ZIP 放入 .tools/temurin-jre8-windows-x64.zip，下载地址和校验值见 third_party/runtime.json。
FlatLaf 库已包含在 third_party，构建时会校验依赖。原生启动器使用系统自带的 .NET Framework 4.x 编译器。
仅运行自动测试：python tools/build.py --test-only。

packaging 中保存用户使用说明和发布许可文本。便携包包含程序、用户说明和必要许可。
第三方许可见 THIRD_PARTY_NOTICES.txt。内部验证记录不包含在源码 ZIP 中。
