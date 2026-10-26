"""Minimal IKEv2 decoder for a pcap (Ethernet/IPv4/UDP 500 and 4500): one line per message,
then each payload with its critical bit, length and (for cleartext payloads) the bytes."""
import struct, sys

EXCH = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL"}
PL = {33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT", 38: "CERTREQ", 39: "AUTH", 40: "Nonce",
      41: "N", 42: "D", 43: "V", 44: "TSi", 45: "TSr", 46: "SK", 47: "CP", 48: "EAP", 53: "SKF"}
NOTIFY = {14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KE_PAYLOAD", 24: "AUTHENTICATION_FAILED",
          16388: "NAT_DETECTION_SOURCE_IP", 16389: "NAT_DETECTION_DESTINATION_IP",
          16430: "IKEV2_FRAGMENTATION_SUPPORTED", 16431: "SIGNATURE_HASH_ALGORITHMS",
          16384: "INITIAL_CONTACT", 16394: "ESP_TFC_PADDING_NOT_SUPPORTED", 16395: "NON_FIRST_FRAGMENTS_ALSO",
          16390: "COOKIE", 16404: "MOBIKE_SUPPORTED", 16418: "CHILDLESS_IKEV2_SUPPORTED",
          16433: "REDIRECT_SUPPORTED", 16441: "USE_PPK", 16406: "MULTIPLE_AUTH_SUPPORTED"}

def packets(path):
    data = open(path, "rb").read()
    magic = struct.unpack("<I", data[:4])[0]
    end = "<" if magic in (0xa1b2c3d4, 0xa1b23c4d) else ">"
    off = 24
    while off + 16 <= len(data):
        ts, us, incl, orig = struct.unpack(end + "IIII", data[off:off + 16])
        yield ts + us / 1e6, data[off + 16:off + 16 + incl]
        off += 16 + incl

def main(path, verbose):
    t0 = None
    for ts, f in packets(path):
        if len(f) < 42 or f[12:14] != b"\x08\x00":
            continue
        ip = f[14:]
        ihl = (ip[0] & 15) * 4
        if ip[9] != 17:
            continue
        src, dst = ".".join(map(str, ip[12:16])), ".".join(map(str, ip[16:20]))
        sp, dp = struct.unpack(">HH", ip[ihl:ihl + 4])
        ike = ip[ihl + 8:]
        if 4500 in (sp, dp):
            if ike[:4] != b"\0\0\0\0":
                continue  # ESP
            ike = ike[4:]
        elif 500 not in (sp, dp):
            continue
        if len(ike) < 28:
            continue
        ispi, rspi, nxt, ver, ex, flags, mid, length = struct.unpack(">8s8sBBBBII", ike[:28])
        t0 = t0 or ts
        role = ("I" if flags & 8 else "R") + (" resp" if flags & 32 else " req")
        print(f"{ts - t0:7.3f} {src}:{sp} -> {dst}:{dp} {EXCH.get(ex, ex)} mid={mid} {role} flags=0x{flags:02x} "
              f"len={length} spi={ispi.hex()}:{rspi.hex()}")
        off = 28
        while nxt and off + 4 <= len(ike):
            n2, crit, plen = struct.unpack(">BBH", ike[off:off + 4])
            body = ike[off + 4:off + plen]
            extra = ""
            if nxt == 41 and len(body) >= 4:
                ntype = struct.unpack(">H", body[2:4])[0]
                extra = f" {NOTIFY.get(ntype, ntype)}"
            print(f"        {PL.get(nxt, nxt):5} crit={crit >> 7} reserved=0x{crit & 0x7f:02x} len={plen}{extra}"
                  + (f"  {body.hex()}" if verbose and nxt not in (46, 34, 40) else ""))
            if nxt == 46:
                break
            nxt, off = n2, off + plen
        if off + (0 if nxt == 46 else 0) and length != len(ike):
            print(f"        !! IKE header length {length} != UDP payload {len(ike)}")

if __name__ == "__main__":
    main(sys.argv[1], "-v" in sys.argv)
