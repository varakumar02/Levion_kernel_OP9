<div align="center">

#  Ｌｅｖｉｏｎ  Ｋｅｒｎｅｌ


**Levion is a battery-first kernel (60/40 balance) with full NetHunter support.**
Tuned for longer screen-on time, cooler idle temps, and a snappier device — for Internal Injection 😜

[![Device](https://img.shields.io/badge/Device-OnePlus%209%20%2F%209%20Pro-red)](https://github.com/OnePlusOSS/android_kernel_oneplus_sm8350)
[![KernelSU-Next](https://img.shields.io/badge/KernelSU_Next-Supported-green)](https://kernelsu-next.github.io/webpage/)
[![SUSFS](https://img.shields.io/badge/SUSFS-Integrated-orange?logo=gitlab)](https://gitlab.com/simonpunk/susfs4ksu)
[![NetHunter](https://img.shields.io/badge/NetHunter-Supported-557C94?logo=kalilinux&logoColor=white)](https://www.kali.org/docs/nethunter/)
[![qcacld3](https://img.shields.io/badge/qcacld3-Injection-8A2BE2)](https://gitlab.com/kalilinux/nethunter/build-scripts/kali-nethunter-kernel-builder/-/tree/main/patches/5.4?ref_type=heads)

[![aox](https://img.shields.io/badge/aox-base-green)](https://github.com/varakumar02/Levion_kernel_OP9/tree/aox)
[![aox-nh](https://img.shields.io/badge/aox--nh-NetHunter-557C94)](https://github.com/varakumar02/Levion_kernel_OP9/tree/aox-nh)
[![aox-ksun](https://img.shields.io/badge/aox--ksun-NetHunter%20%2B%20KernelSU%20Next-green)](https://github.com/varakumar02/Levion_kernel_OP9/tree/aox-ksun)

<img width="300" height="300" alt="dragonite" src="https://github.com/user-attachments/assets/ebb3fbcb-eec7-40d7-9116-7b3629ac4b0d" />

</div>

---

## ⚠️ Disclaimer

Flashing a custom kernel will not void your warranty, but there is always a risk of bricking your device. Please make sure to:
- 💾 Back up your data and your stock **boot.img**, **vendor_boot.img** and **vendor_dlkm.img**
- 🧠 Understand the features in this kernel before flashing it
- ✅ Tested on **LineageOS 23.2 (Android 16)** only — other ROMs are not guaranteed

- I am **not responsible** for bricked devices, damaged hardware, or any issues that arise from using this kernel.

- By flashing this kernel, **YOU** are choosing to make these modifications. If something goes wrong, **do not blame me**!

<div align="center">

# **🚨 Proceed at your own risk!**
</div>

---

## ✨ Features

Levion is a battery-first kernel (60/40 balance) with full NetHunter support.
Tuned for longer screen-on time, cooler idle temps, and a snappier device — for Internal Injection 😜

#### >_ Base
- \>_ **Linux 5.4.305** with the [OpenELA](https://github.com/openela/kernel-lts) LTS updates (~400 extra security fixes)
- 🏎️ **Clang PGO + LTO**: built with a profile from real OnePlus 9 / 9 Pro use (3–12% faster kernel code)

#### ⚡ Performance & Scheduler
- 🧠 **CASS**: Capacity Aware scheduler for smart, efficient task placement (alongside WALT)
- 🚀 **BORE v5.1.0**: burst-oriented scheduler for a snappier UI
- 🎚️ **uclamp**: per-task min/max performance clamping
- 📈 **WALT** (Qualcomm): window-based load tracking that sizes tasks and picks the CPU frequency, so the CPU ramps up and down faster than with PELT
- ⏱️ **PELT half-life 16ms**: the remaining PELT signals (RT/IRQ load, load balancing) react ~2x faster; task sizing and CPU frequency use WALT
- 🎮 **Adrenoboost**: adjustable GPU boost for smoother gaming — `/sys/class/kgsl/kgsl-3d0/devfreq/adrenoboost` (0–3)
- 🌡️ **cpufreq_bouncing** (OnePlus): caps the big cores under long heavy load to cut heat, **off by default** —
  `echo 1 > /sys/module/cpufreq_bouncing/parameters/enable` to turn on, `echo 0` to turn off
- 🛠️ **Curated YAKT tweaks**: scheduler/VM defaults tuned for daily-driver smoothness

#### 🔋 Battery & Charging
- 💤 **Lazy RCU**: batches kernel housekeeping so the CPUs wake up less often when idle — **backported from Linux 6.2**
- 🔋 **Power-Efficient Workqueues**: background work parked on idle CPUs to save battery
- 📊 **Sleep monitor** (OnePlus `subsys_sleep_monitor`): shows how long the modem/DSPs sleep, for battery debugging
- ⚡ **USB Fast Charge**: up to **900mA** in USB 2.0 mode, **on by default** — `echo 0 > /sys/kernel/fast_charge/force_fast_charge` to disable

#### 💾 Memory & Storage
- 🧬 **MGLRU** (Multi-Gen LRU): smarter memory reclaim, fewer app reloads — **backported from Linux 6.1**
- 🗜️ **ZRAM**: LZ4 by default, with LZ4HC / ZSTD as extra algorithms and writeback support — **multi-compression backported from Linux 6.2**
- 🚀 **LZ4 v1.10.0** with ARM64 assembly: faster compression and decompression — **backported from upstream LZ4**
- 💽 **I/O schedulers**: **ADIOS v3.3.0** (default), plus SSG, mq-deadline, Kyber and BFQ
- 💽 **NTFS3 + exFAT**: full read/write for USB-OTG drives
- ⚡️ **TMPFS XATTR / POSIX ACL**: extended attribute support

#### 🌐 Network
- 🌐 **BBR v3**: Google's latest congestion control for better throughput & latency — **backported from Google's BBRv3 branch**
- 🚦 **FQ Codel**: fair queuing that kills bufferbloat under load
- 📶 **MPTCP Next**: use Wi-Fi + Mobile data together — **backported from MPTCP Next (MPTCP v1, Linux 6.0 level)**
- 🔎 **DNS optimizer**: faster DNS lookups on slow networks
- 🧱 **nftables + ipset**: modern firewall stack
- 🎥 **UVC webcam gadget**: use the phone as a USB webcam — **backported from android16-6.12**

#### 🔐 Root & Security
- 🔐 **KernelSU Next v3.4.2-legacy**: modern kernel-mode root
- 🥷 **SUSFS v2.4.0**: root hiding for better app compatibility (banking, etc.)
- 🛡️ **Baseband Guard**: lightweight LSM protecting critical partitions (modem, bootloader, vbmeta…) from accidental format/tamper
- ✅ **SELinux stays enforcing**: no permissive downgrade

---

## <img src=".github/assets/kali.png" alt="Kali" height="30"> Kali NetHunter Edition

Levion ships with full **NetHunter** support on top of every feature above:

- 📡 **External Wi-Fi adapters**:
  - Realtek: RTL8812AU, RTL8814AU, RTL8821CU (rtw88), RTL8188EUS, RTL8xxxu, RTL8187
  - Atheros: ath9k_htc (AR9271), carl9170, ath6kl
  - MediaTek: MT7601U, MT76x0U, MT76x2U
  - Ralink rt2800usb, ZyDAS ZD1211
- 🛰️ **Monitor mode + injection (external)**: full monitor mode with frame & packet injection on supported USB adapters (mac80211 with radiotap injection flags)
- 📶 **qcacld3 Injection Mode**: internal wireless pentesting straight from the built-in Wi-Fi (WCN3990) — no external adapter needed; injects both unicast and broadcast frames (hybrid Direct-DP + WMI), and monitor mode can run next to a normal Wi-Fi connection and the hotspot
- ᚼᛒ **Bluetooth USB adapters**: including the TP-Link UB500
- 📻 **SDR support**: HackRF, Airspy, MSI2500 (RTL-SDR works through its USB userspace tools)
- 🚗 **CAN bus**: CAN + ISO-TP sockets for car diagnostics tools
- 🕵️ **Stealth network engine**: in-kernel DNS blocking/spoofing, TLS SNI audit, optional ghost modes and a local IDS (`/proc/stealth_dns`, `/proc/stealth_events`)
- 🔌 **USB gadgets**: RNDIS, ECM-subset, EEM and OBEX for USB tethering / networking
- 🧰 **Raw sockets & unrestricted ports**: for tools that need low-level network access
- 🧩 **32-bit (ARMv7) apps and tools**: 32-bit support is on for NetHunter tools
- 📦 **No loadable modules**: every driver and its USB firmware is built into the kernel image

---

## 📋 Installation

The release zip is an **AnyKernel3** package. Pick one way to flash it:

- 🔐 **KernelSU Next app**: Flash with the KernelSU Next app
- 📲 **Kernel Flasher app**: flash with the **[Kernel Flasher](https://github.com/capntrips/KernelFlasher)** app (needs root)
- ♻️ **Recovery**: `adb sideload ./levion_kernel.zip`

Then reboot and install the matching **[KernelSU Next](https://kernelsu-next.github.io/webpage/)** manager app for root. You can also find installation instructions in the release notes.

---

## 💬 Support

If you encounter any issues or need help, feel free to:
- 🐛 Open an issue with a clear description, steps to reproduce, relevant logs (`dmesg`, `last_kmsg`, `logcat`), and your ROM + kernel build version
- 💬 Reach out directly

---

## 🌟 Special Thanks

**These amazing people help make this project possible! ❤️**

<div align="center">

| 🔧 **Contribution** | 👨‍💻 **Developer** | 🔗 **Link** |
|:---------------:|:----------------:|:-----------:|
| **BBR v3 · FQ-CoDel**<br>**MPTCP Next · Lazy RCU · ZRAM**<br>**qcacld3 injection** | Madara273 | [![GitHub](https://img.shields.io/badge/GitHub-Madara273-blue?style=flat-square&logo=github)](https://github.com/Madara273) |
| **5.4 LTS updates** | OpenELA | [![GitHub](https://img.shields.io/badge/GitHub-openela-blue?style=flat-square&logo=github)](https://github.com/openela/kernel-lts) |
| **BORE scheduler · ADIOS I/O scheduler** | Masahito Suzuki | [![GitHub](https://img.shields.io/badge/GitHub-firelzrd-blue?style=flat-square&logo=github)](https://github.com/firelzrd) |
| **CASS scheduler** | Sultan Alsawaf | [![GitHub](https://img.shields.io/badge/GitHub-kerneltoast-blue?style=flat-square&logo=github)](https://github.com/kerneltoast) |
| **SSG I/O scheduler port** | freak07 | [![GitHub](https://img.shields.io/badge/GitHub-freak07-blue?style=flat-square&logo=github)](https://github.com/freak07) |
| **KernelSU Next** | rifsxd | [![GitHub](https://img.shields.io/badge/GitHub-rifsxd-blue?style=flat-square&logo=github)](https://github.com/KernelSU-Next/KernelSU-Next) |
| **SUSFS** | simonpunk | [![GitLab](https://img.shields.io/badge/GitLab-simonpunk-orange?style=flat-square&logo=gitlab)](https://gitlab.com/simonpunk/susfs4ksu.git) |
| **Baseband Guard** | vc-teahouse | [![GitHub](https://img.shields.io/badge/GitHub-vc--teahouse-blue?style=flat-square&logo=github)](https://github.com/vc-teahouse/Baseband-guard.git) |

</div>

<div align="center">

### 💖 Huge thanks to **[@Madara273](https://github.com/Madara273)** ❤️

</div>

*If you have contributed and are not listed here, please remind me!* 🙏

---

<div align="center">

### ⚡ **Built for the OnePlus 9 / 9 Pro — fast, rooted, and pentest-ready.** ⚡

</div>
