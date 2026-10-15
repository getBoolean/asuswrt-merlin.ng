# UniFi adoption of an Asuswrt‑Merlin router — feasibility research

**Goal:** have a UniFi gateway/controller (UDM/UCG/UXG running UniFi Network
Application) **adopt** an Asus router running Asuswrt‑Merlin and fully **manage**
it as a UniFi access point + in‑wall switch: SSIDs/security/radios, VLANs
(tagged networks + SSID↔VLAN binding + per‑port profiles), network settings, and
show every connected wired/wireless client with stats.

**Status:** research / feasibility only. No firmware was modified. This document
is the plan; no adoption agent is shipped here.

> Scope note: the design has the Asus act as an **AP + switch that the UniFi
> gateway manages**. It does **not** emulate a UniFi gateway (USG/UXG) — a UniFi
> site rejects a second gateway (`api.err.NoSecondGateway`), and routing /
> inter‑VLAN firewalling / DHCP stay on the real UniFi gateway by design.

---

## 1. Verdict

**Feasible, and buildable as a pure Asuswrt‑Merlin `/jffs` addon** (no firmware
fork) on modern Broadcom HND models, reusing **MerVLAN** for the VLAN data‑plane
(with credit) and porting the inform/adoption control‑plane from the MIT‑licensed
**openUF** project. The decisive facts, verified against the **current** UniFi
Network Application **10.6.106** and the Merlin **3006** source tree:

1. **The controller has no hardware root of trust for adoption.** There is no
   device certificate, secure‑element, or signed‑firmware check in the inform or
   adoption path. Device authenticity = a shared AES key + a model id that exists
   in the controller's device database. (§3)
2. **The config the controller pushes is still AirOS‑style `system_cfg`
   key=value text** — `aaa.*`, `wireless.*`, `radio.*`, `vlan.*`, `switch.port.*`
   — not an opaque/attested blob. Verified in the 10.6.106 generator. (§4)
3. **Merlin can both apply and report what the protocol needs.** It ships
   OpenSSL 3.5.9 (AES‑GCM), zlib, libcurl, json‑c; exposes all the Wi‑Fi/VLAN
   nvram keys and `service restart_*` hooks; and already has a working VLAN addon
   (MerVLAN) and a controller/agent analogue (AiMesh `cfg_server`/`cfg_client`) to
   model the design on. (§5–§8)

**What will not be perfect** (set expectations up front): genuine UniFi APs will
tag the Asus as a third‑party/rogue AP (we don't emit Ubiquiti's beacon IE); fast
roaming (802.11r) between the Asus and real UniFi APs won't work; there's **no PoE
control** anywhere in Merlin; LAN ports behind an external switch chip (e.g.
RT‑AX88U's BCM53134, Realtek on some BE models) aren't individually controllable;
and the inform/config formats can change in a future controller release, so the
agent must be version‑aware and fail safe.

---

## 2. Prior art (build on these, don't start cold)

| Project | What it is | Relevance |
|---|---|---|
| **openUF** — active forks `jonasevcik/openUF` (commit 2026‑10‑13), `yesrab`; **MIT** | Lua inform/adoption daemon for **OpenWrt**. Verified adopted to *Connected* by a **real UCG on Network 10.4.57 and 10.6**, receiving VLAN‑tagged SSIDs (WPA2/WPA3), radio settings, 802.11r/k/v, client block/kick; shows wired+wireless clients in topology. Poses as **U6‑InWall**. | **The control‑plane to port.** Its OpenWrt backend (`ucihelper.lua`, `netmodel.lua`) is the layer we replace with a Merlin backend. AP‑only; USW/USG not implemented. |
| **MerVLAN** — `r80xcore/mervlan` | Asuswrt‑Merlin **/jffs addon**, AP‑mode only, per‑SSID + per‑eth‑port VLAN tagging via `ip link … type vlan` + per‑VLAN bridges, `services-start`/`service-event` hooks, self‑heal cron, multi‑node SSH sync, web UI under LAN → MerVLAN. | **The VLAN data‑plane to reuse (with credit).** Already solves per‑SSID/per‑port tagging on HND. |
| `amd989/unifi-gateway` (was stephanlascar→qvr) | Python, poses as a USG; stats only | Reference for the inform state machine; **not** our role (can't coexist with a real gateway). |
| `jamesbraid/unifi-emu` (Go), `mrder/unifi-bridge` (Py) | Fake device fleets / a D‑Link switch adopted as `USXG24` | Protocol cross‑references; unifi‑bridge shows newer *switch* model ids are rejected ("unknown model") while older ones adopt. |

> On "openUF is 10 years dead": the **original** `trueserve/openUF` (~2015) is a
> dead stub — correct. The **2026 forks above are current and working on 10.6**.
> We treat openUF as a reference to port from, not a dependency; the Merlin
> backend is net‑new either way.

---

## 3. The adoption handshake and why there's no hardware gate

Source of truth: UniFi Network Application **10.6.106**
(`linuxserver/unifi-network-application`), `internal-dependencies.jar` decompiled
with Vineflower; a live controller of that version was stood up in a lab and set
up through its own API to confirm behaviour.

### 3.1 Transport (TNBU "inform")

Device↔controller is the AirOS **TNBU** protocol over HTTP (default port 8080),
servlet `com/ubnt/net/InformServlet.java`. Packet = 40‑byte header + body, all
integers big‑endian:

| off | len | field |
|----:|----:|-------|
| 0 | 4 | magic `TNBU` (int `1414414933`) |
| 4 | 4 | packet version (0) |
| 8 | 6 | device MAC |
| 14 | 2 | flags: `0x1` encrypted · `0x2` zlib · `0x4` snappy · `0x8` AES‑GCM |
| 16 | 16 | IV / GCM nonce |
| 32 | 4 | data version (must be `1` = JSON) |
| 36 | 4 | payload length |

Crypto (`com/a/a/RxFvcetMTlkSFFxK.java`): AES‑128 with the 16‑byte device
**authkey**. CBC = `AES/CBC/PKCS5Padding`; **GCM = `AES/GCM/NoPadding`, 128‑bit
tag, and the whole 40‑byte header is the AAD.** Compression is zlib (`0x2`) or
snappy (`0x4`). Factory‑default authkey is `MD5("ubnt")` =
`ba86f2bbe107c7c57eb5f2690775c712`.

**Adoption flow:** device informs with the default key → user clicks Adopt →
controller replies `setparam` whose `mgmt_cfg` carries a fresh random `authkey`
(+ `inform_url`, `cfgversion`, `use_aes_gcm=true`) → device informs thereafter
with the new key. Before the click, pending informs get HTTP 404 (normal). L3
adoption (device points itself at the controller via `set-inform`) avoids the L2
SSH path (controller SSHes in as `ubnt`/`ubnt` — not how Merlin's sshd works, so
use L3).

### 3.2 What the controller actually checks

- **No hardware attestation.** The only Ed25519 code in the adoption path
  (`service/device/a/unLiwXHYlFDg.java`) generates the **controller's own**
  keypair at boot (`afterPropertiesSet()` → `KeyPairGenerator`) and signs/verifies
  with it — an internal token, not a check of the device. No device cert, no
  secure element, no firmware‑signature check gates adoption. Live proof: openUF
  adopts on a real UCG running 10.6 while reporting its MAC as the serial.
- **AES‑GCM is effectively mandatory for a current model**, but it is **not a
  hardware gate** — it's the shared‑key AES layer in GCM mode. The controller
  writes `use_aes_gcm=true` and won't fully provision a modern model until it gets
  a genuine GCM inform; the GCM state is read from the packet's wire flag
  (`x_aes_gcm`, `data/hyFnQ.java:4702`) so it can't be faked in the payload, and a
  later downgrade to CBC is rejected. Implication: **implement AES‑128‑GCM** (16‑B
  nonce, header as AAD, 128‑b tag). Merlin's OpenSSL 3.5.9 does this trivially.
- **Model identity must be known.** `model`/`sysid` must resolve in the device DB
  (`dl/uidb/uidb.json`, 688 models). Unknown/unsupported/EOL models are refused
  ("unable to manage dev[…]"). Header MAC must equal payload `mac`.
- **Default‑key use is state‑checked**, not blocked: the default key is accepted
  for adoption but refused once the device is past the adoption states — which is
  exactly the normal "switch to your assigned key" flow.

**Net:** the gate is *shared secret + plausible model id*, both supplied in
software by a cooperating agent on the Asus.

### 3.3 Which UniFi model to present

Pick a class that has **both radios and controller‑managed switch ports with
per‑port VLANs** — the in‑wall AP family carrying capability
`ACCESS_POINT_SWITCH` (`i/g/a/hyFnQ.java`):

- **U6‑IW** (`U6IW`, sysid `0xA652`): 2 radios, 5 ports (1 uplink + 4 managed) —
  best fit for a dual‑band Asus in AP mode. (openUF's validated identity.)
- **U6‑Enterprise‑IW** (`U6ENTIW`, `0xA682`): tri‑band + 2.5 GbE — closer to a
  tri‑band GT/BE Asus.
- **UAP‑AC‑IW / UHD‑IW**: AC‑class analogues for Wi‑Fi 5 Asus models.

`ACCESS_POINT_SWITCH` is what makes the controller render/push per‑port VLAN
profiles on the device's integrated switch, which is what unlocks "VLANs + port
management + all clients" rather than an AP with a lone uplink.

---

## 4. The config the controller pushes (verified on 10.6.106)

The 10.6.106 generator (`com/ubnt/service/config/VAZShipWTNxlo.java`) still emits
AirOS‑style `system_cfg` **key=value text**. The keys the Merlin backend must
parse/translate:

**WLAN / security (per BSS `n`):**
- `aaa.<n>.ssid`, `aaa.<n>.wpa.psk`, `aaa.<n>.wpa.key.<k>.mgmt`, `aaa.<n>.pmf.mode`
- `wireless.<n>.*`, `radio.<n>.*` (channel, country, bandwidth, outdoor, 6 GHz AFC…)
- **WPA‑Enterprise is present in 10.6**: `aaa.<n>.radius.auth.<k>`,
  `aaa.<n>.radius.acct.<k>`, `aaa.<n>.radius_acct_send_keyid` (this did **not**
  exist in the 10.4 write‑ups — a genuine "UniFi changed" delta, in our favour).

**SSID → VLAN binding:**
- `aaa.<n>.br.devname = br0.<vlan>` — the VAP is bridged onto a VLAN sub‑interface.

**Per‑port switch VLAN (AP‑with‑switch identity; needs `fw_caps` bit `0x100`
`hasOWRTSwitch`):**
- `switch.vlan.status`, `switch.dot1x.status`
- `switch.port.<idx>.status` (enabled/disabled), `.pvid`, `.opmode`, `.name`,
  `.dot1x.mode`, speed/duplex/flowctrl
- per‑VLAN port membership with mode `untagged` / `tagged` / `exclude`

This is the exact translation target. It gives native + tagged VLANs per port and
per SSID — enough for the user's goal — though not every USW feature (no PoE, no
storm‑control, etc.).

---

## 5. Merlin backend — applying pushed config

> **Key constraint:** the apply/report logic ships as **closed prebuilt
> binaries** (`rc/prebuild/<MODEL>/amas_apg.o` for VLAN/SSID apply, `broadcom.o`
> for `GetPhyStatus`, `shared/prebuild/<MODEL>/notify_rc.o`, plus `networkmap`,
> `cfg_mnt`). You drive them via **nvram + `service restart_*`**; you can't modify
> them. This is why the addon model (drive through nvram) is the right fit.

### 5.1 WLAN
Map pushed WLAN keys onto Asus nvram and restart:
- `aaa.<n>.ssid` → `wlX[.Y]_ssid` (`shared/defaults.c:103`); enable → `_bss_enabled`
  (`:129`); hidden → `_closed` (`:258`); isolate → `_ap_isolate` (`:259`)
- security → `_auth_mode_x` (`:745`), `_wpa_psk` (`:588`), `_crypto` (`:607`),
  `_mfp` (`:616`); radio → `_chanspec` (`:315`), `_txpower` (`:777`), `_bw` (`:715`)
- apply: `notify_rc("restart_wireless")` → `restart_wireless()` (`rc/lan.c:6615`)
- Guest/virtual BSS: `wlX.1 … wlX.3` (MAX 4 incl. main, `shared/shared.h:1736`).

### 5.2 VLANs — two paths, choose by platform
- **(a) Stock SDN/APG model** on **MTLANCFG (3006)** models (GT‑AX6000, RT‑AX86U
  Pro, RT‑AX88U Pro, GT‑AX11000 Pro, GT‑AXE16000, XT12, RT‑BE96U, GT‑BE98 Pro,
  RT‑BE88U, RT‑BE86U, RT‑BE92U, RT‑BE58 Go). Write the `<`/`>`‑delimited records
  (`shared/mtlan_utils.c`): `vlan_rl` (`:153`), `subnet_rl` (`:203`), `sdn_rl`
  (`:412`), SSID↔VLAN via `apgN_*` + `apgN_dut_list` (`shared/amas_apg_shared.h`),
  trunk ports via `vlan_trunklist`; apply with `restart_apg` / `restart_net_and_phy`.
  **Pros:** ASUS‑supported, persistent, uses `vlanctl` (matches HND flow accel),
  shows in the stock UI, handles external switch chips via the closed
  `apg_switch_vlan_set`. **Cons:** 3006 only; closed; formats may shift between
  releases.
- **(b) MerVLAN‑style scripted layer** elsewhere (incl. 3004 HND): `ip link add
  link <uplink> name X.<vid> type vlan` + a `br<vid>` bridge per VLAN, moving
  `wlX.Y` VAPs / `ethN` ports out of `br0` (`functions/mervlan_manager.sh`),
  re‑applied on `services-start`/`service-event` + a heal cron (rc keeps rebuilding
  `br0`). **Pros:** portable, transparent, fully under our control. **Cons:**
  fights rc; per‑model port maps; no access to ports behind an external switch.
  *(Correction to a common assumption: MerVLAN does **not** use `robocfg` — that
  tool is from the pre‑HND 386 branch and isn't in the 3006 tree.)*

**Recommendation:** path (a) on MTLANCFG models, (b) as fallback. Translating
UniFi networks/port‑profiles into the SDN model is the portable choice on 3006.

### 5.3 Critical AP‑mode DHCP caveat
In AP mode (`sw_mode=3`) tagged VLANs + per‑SSID tagging toward an upstream
gateway do work (VLAN UI stays available in AP mode; `sdn.js` allows VLAN IDs
3–4093 when "use main subnet" is off). **But** open `rc/sdn.c` does not disable
per‑SDN dnsmasq in AP mode — so set `dhcp_en=0` in the `subnet_rl` record for each
network, so the **UniFi gateway** serves DHCP (which is what the user wants).
Verify on hardware.

---

## 6. Merlin backend — reporting state to the controller

The agent builds the inform JSON tables the controller consumes (`radio_table`,
`vap_table`, `sta_table`, `port_table`, `sys_stats`), using open Merlin code paths:

- **Wireless clients** (easiest): mirror `httpd/sysdeps/web-broadcom-am.c:353‑720`
  — walk each VAP's `authe_sta_list`, call `sta_info <mac>` for RSSI, tx/rx rate,
  connected time, NSS, PHY, bandwidth; VLAN via `get_apg_vid_by_ifname`; merge
  `/proc/net/arp` + dnsmasq leases (incl. per‑SDN `dnsmasq-N.leases`). Shell
  equivalent: `wl -i wlX.Y assoclist` / `sta_info`.
- **Port link/stats** (HND = each port is its own netdev):
  `/sys/class/net/ethN/statistics`, `ethtool`, `ethswctl`; or `rc phy_info` /
  `rc port_status` / `/get_port_status.cgi` (closed `GetPhyStatus`). Port
  up/down: `ethctl_set_phy(ifname,0|1)` (`shared/boardapi.c:1258`). **No PoE.**
- **Also available:** networkmap shm (key 1001, `CLIENT_DETAIL_INFO_TABLE` with
  vlan_id/sdn_idx/band/rssi/ssid), and `/tmp/clientlist.json`,
  `/tmp/wiredclientlist.json` written by `cfg_mnt`.

---

## 7. Packaging as a `/jffs` addon (no firmware rebuild)

Confirmed against the tree:

- **Hooks** run by `run_custom_script()` (`shared/scripts.c:54`), gated on
  `jffs2_scripts=1` (default 0 — user enables "Custom JFFS Scripts"). Fire sites:
  `services-start` (`rc/services.c:13536`, async, start the daemon here),
  `service-event` / `service-event-end` (`:15915` / `:22519` — re‑apply on wireless
  restarts; **service-event blocks rc up to 120 s, so return fast**),
  `firewall-start`, `nat-start`, `init-start`, `wan-event`. Custom service names
  (e.g. `restart_unifiagent`) still reach `service-event`, which is how the addon's
  UI triggers addon actions.
- **Layout** `/jffs/addons/<name>/` (`setup_jffs_dirs`, `scripts.c:142`). `/jffs`
  is a separate jffs2/UBIFS partition (`rc/jffs2.c:409`) — **survives reboot and
  firmware flash**; wiped only by format/factory‑reset.
- **Web UI:** `am_addons` capability (`rc/init.c:23233`); publish `user<N>.asp`
  into `/www/user` (tmpfs) on each boot; register the tab by bind‑mounting an
  edited `/tmp/menuTree.js` (as MerVLAN does, `install.sh:1367`); store settings
  via `am_settings_get/set` → `/jffs/addons/custom_settings.txt`
  (`others/helper.sh`).
- **Binaries/libs:** Entware lives on USB → **not** suitable for a portable addon.
  The firmware already ships `libcrypto.so.3`/`libssl.so.3` (OpenSSL 3.5.9, AES‑GCM
  via EVP), `libz`, `libjson-c`, `libcurl`, `/usr/sbin/openssl`, `/usr/sbin/curl`.
  So the agent can be shell + `openssl`/`curl`, or ported from openUF's Lua, or a
  small C daemon cross‑compiled with the matching toolchain (gcc 13.2/glibc 2.38).
  **snappy is absent** from the tree — fine, use **zlib** compression (flag `0x2`),
  which the protocol supports.

---

## 8. AiMesh is the design template

Merlin/ASUS already run a controller→agent config system: `cfg_server` (main) and
`cfg_client` (node) — closed binaries using RSA key exchange + AES‑256, nodes
reporting every ~30 s, with a **table‑driven param→feature→rc‑service** mapping
(`cfg_param.h`): e.g. `sdn_rl` → `restart_apg`, `vlan_trunk_rl` →
`restart_net_and_phy`, `ap_wifi_rl`/`wl0_ssid` → `restart_wireless`. The UniFi
agent should mirror exactly this shape: receive config → map to nvram keys →
restart the right service → report state back.

---

## 9. Legal / licensing

- Reverse engineering **for interoperability** has statutory cover: US **DMCA
  §1201(f)** and **EU Directive 2009/24/EC Art. 6** permit decompiling to the
  extent needed to make an independently created program interoperate. This
  project is squarely interoperability.
- Ship **none** of Ubiquiti's firmware/software; reimplement the wire protocol
  clean‑room from protocol facts (never fetch or bundle UniFi firmware — openUF
  takes the same stance). Ubiquiti's EULA bars RE "except … to the extent such
  activities may not be prohibited under applicable law."
- Build on **openUF under MIT** (attribution in `NOTICE`) and **MerVLAN with
  credit** per its LICENSE. Trademark use of model names ("U6‑IW") in adoption is
  a separate question from copyright — present the identity for interoperability,
  don't market the product as a UniFi device.
- This is unofficial; a controller update can change the handshake. The agent must
  be version‑aware and fail safe. **Not legal advice.**

---

## 10. Recommended build order

1. **Control plane:** port openUF's inform engine (framing in
   `reference/inform_framing.py`) to the Merlin runtime; L3 adoption against a lab
   controller (UniFi Network Application 10.6.106 was used for this research).
2. **Merlin backend:** `system_cfg` parser → WLAN‑nvram + VLAN translator
   (path (a)/(b) per §5); state collector for the inform tables (§6).
3. **One reference model first** (e.g. RT‑BE96U or RT‑AX86U Pro → U6‑IW): validate
   adopt → SSID push → VLAN push → port profile → client list end‑to‑end, then
   widen the model map and the per‑model port tables.
4. **Package** as `/jffs/addons/unifi-adopt/` with an Addons‑tab UI (§7); document
   the **AP mode + wired‑backhaul + `dhcp_en=0`** requirements and the known
   limitations (§1).

---

### Appendix — source pointers
- Controller (10.6.106, decompiled): `com/ubnt/net/InformServlet.java` (transport),
  `com/a/a/RxFvcetMTlkSFFxK.java` (crypto), `com/ubnt/service/config/VAZShipWTNxlo.java`
  (`system_cfg` generator), `com/ubnt/service/device/a/unLiwXHYlFDg.java` (internal
  token), `dl/uidb/uidb.json` (device DB).
- Merlin tree paths are cited inline, relative to `release/` (e.g.
  `shared/defaults.c`, `rc/services.c`, `shared/mtlan_utils.c`,
  `httpd/sysdeps/web-broadcom-am.c`, `shared/scripts.c`).
- Prior art: `jonasevcik/openUF` (MIT), `r80xcore/mervlan`.
