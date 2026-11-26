# 5125 TLS-PSK 指纹传感器逆向 — 进度 (2026-08-05)

## 目标
让 Goodix 27c6:5125 指纹模块（TLS-PSK 加密通道）正常工作，捕获并解码指纹图像。

## 当前状态
- ✅ **完整管线已打通**：PSK blob → 捆绑式 TLS 中继 → config → FDT → 抓帧 → openssl 解密 → 80×64 图像解码
- ✅ **真实指纹帧已捕获**（ASCII 渲染清晰显示拱形脊线，score 18→325，mean 4079→3297）
- ✅ **fprintd 驱动打通（今日决定性突破）**：ZERO PSK + 0xd4 非致命 → `claimed device 0`，enroll 管线 FDT→DAC→0x20 全通
- ✅ **WebAuthn 链实证**：Chromium 150 WebAuthn 测试触发 fprintd IDENTIFY（journal 实证），浏览器→fprintd→驱动全链接通
- ✅ **WebAuthn 测试台**：`/tmp/webauthn-test/`（index.html 交互台 + auto-check + auto-register），python3 http.server 8899 @127.0.0.1 运行中
- ⏳ **enroll/match 实机验证**：需真人按传感器（fprintd-enroll 21 阶段）— 当前 tmux `enroll` 会话等待手指按压

## 已完成

### 1. 握手结构验证（2026-08-03 晚）
- avail 结构修复 100% 正确（0xd4 ACK、3 条消息、双 prebulk 对齐 WBDI/avail）
- PRESET_PSK_READ(0xe4) 返回磁盘 psk 文件内容（PMK 哈希，非会话密钥）
- 512B DPAPI blob 直通（cmd 0xff）后 ZERO PSK 握手在记录层成功

### 2. TLS 突破：捆绑式中继（决定性）
- `tool.connect_device` 式中继：ServerHello+SKX+SHD 一个 0xb0 包 + CCS+Finished 一个包，
  不拆分、无 prebulk、无 sleep
- 结果 `state=00023100000800002000000011200000`、`isTlsConnected=True`
- avail 拆包式 → `state=00003000...`、`isTlsConnected=False`
- **结论：拆包破坏芯片对 server Finished 的校验**

### 3. config 上传修复
- RAW_DEVICE_CONFIG 已是完整 pack，raw 直写（upload_config_mcu 双重封装会失败）
- raw 直写后 ack cmd=0x90、has_no_config=False、reply 0100 ret=1

### 4. openssl close_notify 根因（关键排障）
- 握手后 s_server 立即发 close_notify 拒绝应用数据 → **stdin EOF**
- 非交互 shell 继承 /dev/null → s_server 见 EOF 即优雅关闭
- 修复：`subprocess.Popen(..., stdin=subprocess.PIPE)` 持有不关闭
- 隔离测试确认客户端明文正常输出到 stdout

### 5. 图像管线（今日突破）
- mcu_get_image → 7726B RAW（flags=0xb0），body 是 TLS 应用数据记录（17 03 03 1e25）
- 转发 body 给 openssl → 7693B 明文（= 7717 加密 - 16 GCM tag）
- 最优解码偏移 8，80×64 12-bit（7680B）
- 空白帧：mean=4079、hist 全在 bucket 6-7（FDT 返回 ff01 无手指）
- **手指帧：mean=3297、score=325、hist 4/5/6/7 高对比（FDT 返回 a401a9...）**

### 6. fprintd 驱动打通（2026-08-05，决定性）
- **根因**：`/var/lib/fprint/goodix-5125/psk` 存的是 REAL_PSK，但芯片 08-04 重刷后被预置为 **ZERO PSK** → TLS 握手停滞 → 历史所有 enroll "failed to claim device: Timeout"
- **修复 1**：备份 REAL_PSK 到 `psk.real-backup`，psk 文件改写为 32 个零字节 → fprintd 内 TLS 握手**成功**（TLS_HANDSHAKE_STAGE completed successfully）
- **修复 2（代码）**：握手后驱动补发 0xd4(TLS_SUCCESSFULLY_ESTABLISHED) 确认，但 TLS 建立后芯片不再 ACK 明文协议命令（Python 侧已证实）→ `open_tls_complete` 把该超时当致命错误传播 → open 必失败。改 `goodix5125.c open_tls_complete` 将该超时降级为 warning 非致命，重建安装 libfprint
- **结果**：`claimed device 0`、`Image device open completed` — 项目史上首次 fprintd 成功 claim
- **enroll 管线验证**：FDT 检测（Finger present 1）→ OTP DAC 寄存器写入（0x80）→ 0x20 抓帧 **Completed command: 0x20** — 全通
- fprintd 1.94.5 + libfprint 1.94.10（fork-goodixtls 补丁版，单体编译于 /usr/local/lib/x86_64-linux-gnu/libfprint-2.so）

## 下一步
1. **enroll/match 实机验证（阻塞）**：`fprintd-enroll root right-index-finger` 需真人按传感器 21 阶段（tmux `enroll` 会话已在等待）
2. 网站 2FA 指纹：enroll 完成后 Chromium 150 headed 打开 `http://127.0.0.1:8899/` 走 passkey 注册/验证（fprintd journal 观察）
3. 图像质量评估（对比 53xd 工作机的清晰度）
4. 沉淀成果到 Obsidian 笔记库（✅ 已完成：`/root/Documents/Notes/Hacking/Goodix-5125-指纹传感器-驱动打通.md`）

## 看门狗实证（08-05 新增）
- **空闲 FDT 轮询超 ~25 分钟会楔死芯片**：enroll 会话空转等手指，`fprintd-list` 从正常 → 挂起 25s+（18:45 正常 → 19:06 挂起）。
- **复方疗法**：`tmux kill-session -t enroll` + `pkill -9 fprintd`（释放设备）→ `systemctl reset-failed fprintd && systemctl restart fprintd` → 静置几分钟 → `fprintd-list` 恢复即时响应（EXIT=0）。越探越死，静置为先。
- **结论**：enroll 会话绝不能无手指空转 >10 分钟。用 `/tmp/webauthn-test/start_enroll.sh` 一键起会话后立即按手指。
- **当前状态**：fprintd 健康（fresh daemon）、设备在线、无已登记指纹、WebAuthn 服务器 8899 在线。万事俱备，只欠手指。

## 核心文件
- `exp_img_capture.py` — **整合抓图脚本**（一条命令出 PGM/PNG）
- `exp_tls_bundled.py` — 捆绑式中继验证
- `exp_img_raw.py` — 7726B 帧捕获
- `exp_img_decrypt2.py` — openssl 解密（stdin=PIPE 修复版）
- `fp/goodix-fp-dump/tool.py` — connect_device 捆绑式中继、decode_image
- `fp/goodix-fp-dump/goodix.py` — Python 协议层
- `fp/goodix-fp-dump/driver_53xd.py` — 53xd 工作机参考（读 7684 剥 4B）
- `/tmp/5125_finger.pgm` / `/tmp/5125_finger.png` — 真实指纹图像
- `fp/HANDOFF.md` — 完整交接文档

---

## 2026-11-26 最终解决：换成上游完整方案 + Goodix 匹配引擎

**状态：✅ 指纹录入与验证全部通过，功能可用。**

- 调研结论：64×80 图像太小，NBIS/SIGFM 找不到足够特征点，自研抓取+放大路线走不通；成熟方案都用 Goodix 专有匹配引擎。
- 采用 `arbnorme/libfprint-goodix5125`（libfprint 1.94.100 + `goodixtls5125` 驱动 + 从微软更新目录提取的 `AlgoChicago.dll`，实测加载的是 Milan_v_3.02.00.15 引擎）。
- 源码 `/root/Projects/goodix5125-upstream`；meson 构建参数 `-Ddrivers=goodixtls5125 -Dudev_hwdb_dir=/usr/lib/udev/hwdb.d -Ddoc=false`，安装到 `/usr/local`。
- 引擎放在 `/usr/lib64/libfprint-2/goodix5125/AlgoChicago.dll`，fprintd drop-in `goodix5125-engine.conf` 设 `GOODIX5125_ENGINE_DLL`。
- **关键排障**：旧库备份 `libfprint-2.so.2.0.0.aug-backup` 留在库目录里，被 ldconfig 注册成 `libfprint-2.so.2` 且优先级更高 → fprintd 一直加载旧驱动，按手指无反应。备份移到 `/root/fp-backup/` + `ldconfig` + 重启 fprintd 后解决。
- 结果：`fprintd-enroll root right-index-finger` 13/13 成功；`fprintd-verify root` → `verify-match`，引擎 score 32（阈值 30）。
- 前端：黑白 Web 控制台 `/root/fp-webui/`（127.0.0.1:8899），桌面快捷方式 `~/Desktop/Fingerprint Console.desktop`；传感器有 FDT 等待，按手指会实时显示进度。
- 旧驱动 hang 的真正原因：SCAN5125_GET_IMG 无条件 report finger present，0x20 后卡在 `s_server` stdout 管道读取；新驱动有正确 FDT 轮询。

## 2026-11-27 补充：登录时传感器掉线

- 现象：每次冷启动后 `27c6:5125` 正常枚举，但 `lightdm` 登录时 `pam_fprintd` Claim 设备后几秒，内核报 `usb 1-7: USB disconnect`（libusb errno=5），此后一直 `error -71/-110`，只能再冷启动恢复。11-26 17:03:12 与 11-27 13:30:48 两次日志完全一致。
- 结论：不是模板丢失，也不是驱动构建坏了；是 PAM/lightdm 触发的 USB 设备掉线。传感器集成在电源键上，登录阶段的 claim 流程会把它打死。
- 处理：已在 `/etc/pam.d/common-auth` 注释 `pam_fprintd.so`，登录改为纯密码；指纹仅通过 Web 控制台/CLI 手动使用。备份在 `/root/fp-backup/common-auth.with-fprintd.bak`。
