# Cross-vendor pairs, two networks without strongSwan, rekey soak (2026-10-24)

Until now every tunnel in the GNS3 lab had strongSwan on one side. These runs pair the
other generators with each other and add a rekey test. GNS3 2.2.61, strongest common profile.

| Run | Pair | Result |
|---|---|---|
| `--nodes panos,mikrotik` | PAN-OS 12.2.3 ↔ MikroTik CHR 7.24.5 | first run failed (no IKE SA); passed after a PAN-OS generator fix |
| `--nodes vyos,mikrotik --lans 2` | VyOS rolling ↔ MikroTik, 4 subnet pairs | passed: 8/8 pings, child SAs 4 of 4 |
| `--nodes strongswan,mikrotik --rekey 300` | strongSwan 6.1.0 ↔ MikroTik | passed: 450/450 replies over 900 s, IKE and child SAs rekeyed, 1 IKE SA at the end |
| `--nodes strongswan,panos --rekey 300` | strongSwan 6.1.0 ↔ PAN-OS | passed: 450/450 replies over 900 s, IKE and child SAs rekeyed, 1 IKE SA at the end |

## PAN-OS ↔ MikroTik

Profile: IKE AES-256-CBC / SHA-384 / group 20, ESP AES-256-GCM / PFS 20. Neither side had an
IKE SA after the first run. Two separate problems, found with RouterOS `ipsec` debug logging:

1. **MikroTik starts IKE on UDP 4500.** RouterOS sent its IKE_SA_INIT from and to port 4500.
   PAN-OS answered NO_PROPOSAL_CHOSEN (and logged nothing), although the proposal matched
   exactly. The tool's PAN-OS gateway had NAT traversal off, and PAN-OS rejects IKE on 4500
   then. With `protocol-common nat-traversal enable yes` on the gateway PAN-OS accepted it and
   the tunnel came up. **Fix:** the PAN-OS generator now always enables NAT-T on the gateway
   (harmless without NAT; the tool's MikroTik config already has `nat-traversal=yes`).
   The rerun passed, and strongSwan ↔ PAN-OS passed again with the change (rekey run above).

2. **Open: RouterOS rejects PAN-OS as initiator.** When PAN-OS starts the exchange, MikroTik
   decrypts its IKE_AUTH and then logs `identity not found for peer: ADDR4:203.0.113.20` and
   answers AUTHENTICATION_FAILED. The PSK is the same on both sides (when MikroTik initiates,
   both AUTH payloads verify), and it still failed with `remote-id=ignore`, with FQDN IDs,
   with SHA-256 instead of SHA-384, with NAT-T on or off on either side, and with
   `generate-policy=port-override`. Not resolved. In practice the tunnel still comes up:
   MikroTik initiates every few seconds and that direction works, and rekeys run inside the
   IKE SA without a new AUTH. A PAN-OS-only restart waits for MikroTik's next attempt.

Also fixed: the lab's log masking took the PAN-OS keyword `key` (from `pre-shared-key key "…"`)
as a secret, so logs showed `pre-shared-<PSK> <PSK>`. The key itself was always masked.

## Rekey soak

`run.py --rekey 300` (new): the tool's lifetimes become 600 s (phase 1) and 300 s (phase 2),
then every subnet pair is pinged both ways every 20 s for 900 s. strongSwan's SA ages confirm the
rekeys: oldest IKE SA 366 s (MikroTik) and 421 s (PAN-OS) old after a 900 s soak, oldest child
SA about 140 s. No round lost all packets, and the duplicate IKE SAs seen earlier (both ends
initiating) did not pile up: one IKE SA and one child SA toward the peer at the end of both runs.
