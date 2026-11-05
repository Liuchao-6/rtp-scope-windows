# 超哥话探 · Windows

**SIP · RTP 通话分析**

在一个窗口中查看 SIP 交互、回放通话语音、识别按键和定位媒体问题。支持本地离线分析，适用于 **Windows 10 / Windows 11 64 位**。

[下载便携版](dist/ChaogeHuatan-0.5.0-win-x64.zip) · [Android 版](https://github.com/Liuchao-6/rtp-scope-android) · [反馈问题](https://github.com/Liuchao-6/rtp-scope-windows/issues)

## 主要功能

- **抓包导入**：支持 PCAP / PCAPNG，多选或拖放导入，各文件独立分析、切换查看；支持恢复中断抓包。
- **查找通话**：按主叫、被叫、时间段、信令或媒体 IP 组合筛选；列表显示号码和开始时间，选中后查看完整通话。
- **SIP 分析**：按通话展示流序图，点击消息查看源 / 目的 IP、端口、彩色报文和 SDP；支持搜索与复制原文。
- **语音回放**：支持 G.711（PCMA / PCMU）、G.729 / G.729A，可播放双向通话并导出 WAV。
- **按键识别**：支持 RFC 2833 / 4733、SIP INFO、In-band DTMF，显示按键类型、方向和持续时间。
- **波形与质量**：双向波形上下分路、颜色区分，支持缩放和点击定位；标注缺包、按键和到达延迟。播放器可收起。

## 界面预览

SIP 流序图与彩色报文，点击消息查看详情：

![SIP 流序图与彩色报文详情](docs/images/sip-flow.png)

双向媒体波形、按键及质量标记：

![双向 RTP 波形、按键和质量标记](docs/images/rtp-waveform.png)

波形缩放后可区分三类按键：

![缩放波形中的 RFC 2833、SIP INFO 与 In-band 按键](docs/images/dtmf-types.png)

以上均使用合成演示数据，不包含真实通话信息。

## 下载与使用

1. 下载 [便携 ZIP](dist/ChaogeHuatan-0.5.0-win-x64.zip)，**完整解压**后双击 `ChaogeHuatan.exe`。自带运行环境，无需另装 Java。
2. 点击「体验演示」，或通过「导入抓包」 / 拖放打开文件；可一次导入多个文件，再从顶部下拉框切换。
3. 在左侧「找通话」输入号码、IP 或 Call-ID，或点击「筛选」组合主被叫、IP 和时间；选中结果后查看完整流序图，点击消息查看报文。
4. 选择媒体流播放或查看波形。用「− / ＋」或 Ctrl＋滚轮缩放，点击波形或按键标签定位，按需导出 WAV。

如需本机抓包，请先安装 Wireshark / tshark 和 Npcap，再使用「本机抓包」选择网卡。离线分析不需要这些组件。

筛选时间使用本机时区，可填 `14:30:00` 或 `2026-11-05 14:30:00`，可加三位毫秒；匹配在时间段内出现的通话。各条件同时生效，点左侧「全部」清除通话筛选。顶部搜索用于筛选报文或媒体。

## 使用范围

- 语音回放需要完整、未加密且编码受支持的 RTP；暂不解码 AMR、Opus、G.722，不解密 SRTP 或 SIP TLS。
- 缺包与延迟反映抓包位置观察到的情况，不能直接等同于网络实际丢包或终端听感；In-band 按键可能漏检或误判。
- 单文件支持至 **1 GiB（1024 MiB）**，RTP 载荷使用临时磁盘缓存；请为系统临时目录预留至少 2 GB 空间。切换文件或正常退出时清理缓存。
- 最多 2000 万包、3 万条 SIP 消息，TCP 重组上限 24 MiB；单次音频最长 60 分钟。文件列表仅在当前应用会话内保留。
- 当前提供 x64 便携包，需保留 EXE 同目录下的 `app` 和 `runtime` 文件夹。

<details>
<summary>源码构建</summary>

使用 Windows 和 Python 3.11。按 `third_party/toolchain.json` 与 `third_party/runtime.json` 准备 ECJ 编译器及 Temurin 运行环境压缩包，放入 `.tools`，运行 `python tools/build.py`。构建时会校验依赖，生成便携包、源码包和 SHA-256 文件。

仅运行测试：`python tools/build.py --test-only`。

</details>

第三方组件来源与许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
