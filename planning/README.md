# planning/ — UniFi adoption of an Asuswrt‑Merlin router

Planning and feasibility research for making a UniFi gateway/controller adopt and
fully manage an Asus router running Asuswrt‑Merlin as a UniFi **access point +
in‑wall switch** (SSIDs, VLANs, port profiles, all connected clients), shipped as
a Merlin **/jffs addon** that reuses **MerVLAN** (VLAN data‑plane, with credit) and
ports the inform/adoption control‑plane from the MIT‑licensed **openUF**.

Research only — no firmware is modified here.

- **`RESEARCH.md`** — the feasibility report: verdict, the UniFi "inform"/adoption
  handshake and why there's no hardware gate (verified against UniFi Network
  Application 10.6.106), the `system_cfg` config schema the controller pushes, the
  Merlin‑side apply/report integration points (file‑cited), `/jffs` addon
  packaging, prior art, and the legal position.
- **`reference/inform_framing.py`** — clean‑room encode/decode of the documented
  TNBU packet framing (interoperability reference; no impersonation/discovery
  logic). Run it directly for an offline round‑trip self‑test.
