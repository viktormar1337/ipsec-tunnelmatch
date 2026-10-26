"""Recompute an IKEv2 PSK AUTH from a capture (RFC 7296 2.14/2.15).

    python3 -I ikeauth.py <pcap> <g^ir hex> <psk file> [initiator ip]

IKE: AES-CBC-256, HMAC-SHA2-384-192, PRF HMAC-SHA2-384 (the PAN-OS <-> MikroTik profile).
Decrypts the initiator's IKE_AUTH, checks its ICV (proves the keys), then compares the AUTH
it carries with the RFC value and some variants of the signed octets."""
import hashlib, hmac, os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ikedump import packets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

H = hashlib.sha384
prf = lambda k, d: hmac.new(k, d, H).digest()


def prf_plus(k, s, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = prf(k, t + s + bytes([i]))
        out += t
        i += 1
    return out[:n]


def ike_messages(path):
    for ts, f in packets(path):
        if len(f) < 42 or f[12:14] != b"\x08\x00" or f[23] != 17:
            continue
        ip = f[14:]
        ihl = (ip[0] & 15) * 4
        sp, dp = struct.unpack(">HH", ip[ihl:ihl + 4])
        ike = ip[ihl + 8:]
        if 4500 in (sp, dp):
            if ike[:4] != b"\0\0\0\0":
                continue
            ike = ike[4:]
        elif 500 not in (sp, dp):
            continue
        yield ".".join(map(str, ip[12:16])), ike


def payloads(first, data):
    nxt, off, out = first, 0, []
    while nxt and off + 4 <= len(data):
        n2, _, plen = struct.unpack(">BBH", data[off:off + 4])
        out.append((nxt, data[off + 4:off + plen]))
        nxt, off = n2, off + plen
    return out


def main(pcap, gir_hex, psk_file, init_ip=None):
    gir = bytes.fromhex(gir_hex)
    psk = open(psk_file).read().strip().encode()
    msgs = list(ike_messages(pcap))
    # the last IKE_SA_INIT request/response pair that got an IKE_AUTH request, by SPI
    for i in range(len(msgs) - 1, -1, -1):
        src, m = msgs[i]
        if m[18] == 35 and not m[19] & 0x20 and (init_ip is None or src == init_ip):
            auth_msg, spii, spir = m, m[:8], m[8:16]
            break
    else:
        sys.exit("no IKE_AUTH request found")
    req = next(m for s, m in msgs if m[18] == 34 and not m[19] & 0x20 and m[:8] == spii)
    resp = next(m for s, m in msgs if m[18] == 34 and m[19] & 0x20 and m[:16] == spii + spir)
    ni = [b for t, b in payloads(req[16], req[28:]) if t == 40][0]
    nr = [b for t, b in payloads(resp[16], resp[28:]) if t == 40][0]
    print(f"SPIs {spii.hex()}:{spir.hex()}  Ni {len(ni)} bytes  Nr {len(nr)} bytes  g^ir {len(gir)} bytes")
    print(f"IKE_SA_INIT request {len(req)} bytes (header says {struct.unpack('>I', req[24:28])[0]})")

    skeyseed = prf(ni + nr, gir)
    ks = prf_plus(skeyseed, ni + nr + spii + spir, 48 + 48 * 2 + 32 * 2 + 48 * 2)
    sk_d, sk_ai, sk_ar = ks[:48], ks[48:96], ks[96:144]
    sk_ei, sk_er = ks[144:176], ks[176:208]
    sk_pi, sk_pr = ks[208:256], ks[256:304]

    # SK payload of the initiator's IKE_AUTH: IV(16) | ciphertext | ICV(24)
    first = auth_msg[16]
    sk = auth_msg[28:]
    inner_first, _, sklen = struct.unpack(">BBH", sk[:4])
    body = sk[4:sklen]
    iv, ct, icv = body[:16], body[16:-24], body[-24:]
    ok = hmac.compare_digest(hmac.new(sk_ai, auth_msg[:-24], H).digest()[:24], icv)
    print(f"ICV of the IKE_AUTH request: {'OK, keys are right' if ok else 'MISMATCH (wrong g^ir or profile)'}")
    if not ok:
        return
    pt = Cipher(algorithms.AES(sk_ei), modes.CBC(iv)).decryptor().update(ct)
    pad = pt[-1]
    pt = pt[:-(pad + 1)]
    pl = payloads(inner_first, pt)
    names = {35: "IDi", 36: "IDr", 39: "AUTH", 41: "N", 33: "SA", 44: "TSi", 45: "TSr", 38: "CERTREQ", 37: "CERT", 47: "CP"}
    print("decrypted payloads:", ", ".join(f"{names.get(t, t)}({len(b)})" for t, b in pl), f"pad {pad}")
    idi = [b for t, b in pl if t == 35][0]
    auth = [b for t, b in pl if t == 39][0]
    method, value = auth[0], auth[4:]
    print(f"IDi body {idi.hex()}  AUTH method {method}  value {len(value)} bytes")

    keypad = prf(psk, b"Key Pad for IKEv2")
    variants = {
        "RFC: SA_INIT request | Nr | prf(SK_pi, IDi)": req + nr + prf(sk_pi, idi),
        "with Ni instead of Nr": req + ni + prf(sk_pi, idi),
        "with SK_pr": req + nr + prf(sk_pr, idi),
        "IDi with zeroed reserved bytes": req + nr + prf(sk_pi, idi[:1] + b"\0\0\0" + idi[4:]),
        "IDi with its generic header": req + nr + prf(sk_pi, struct.pack(">BBH", 0, 0, len(idi) + 4) + idi),
        "SA_INIT response instead of request": resp + nr + prf(sk_pi, idi),
    }
    for name, octets in variants.items():
        want = prf(keypad, octets)
        print(f"  {'MATCH' if want == value else '     '}  {name}")


if __name__ == "__main__":
    main(*sys.argv[1:])
