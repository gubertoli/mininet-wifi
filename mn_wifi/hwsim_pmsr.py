"""Create PMSR/FTM-capable mac80211_hwsim radios via generic netlink.

Self-contained (Python standard library only). mac80211_hwsim advertises IEEE
802.11 peer measurement (FTM) only on radios whose ``HWSIM_CMD_NEW_RADIO``
carried an ``HWSIM_ATTR_PMSR_SUPPORT`` capability. ``hwsim_mgmt`` does not send
one, so this module issues ``NEW_RADIO`` with a default FTM capability itself,
using the stock in-tree module -- no kernel patch, no external tool.
"""
import socket
import struct

NETLINK_GENERIC = 16
GENL_ID_CTRL = 16
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2

HWSIM_CMD_NEW_RADIO = 4
HWSIM_ATTR_RADIO_NAME = 17
HWSIM_ATTR_PMSR_SUPPORT = 26

# nl80211 peer-measurement capability attributes
PMSR_ATTR_MAX_PEERS = 1
PMSR_ATTR_TYPE_CAPA = 4
PMSR_TYPE_FTM = 1
FTM_CAPA_PREAMBLES = 5
FTM_CAPA_BANDWIDTHS = 6
FTM_CAPA_ASAP = 1
FTM_CAPA_NON_ASAP = 2

NLA_F_NESTED = 0x8000
NLM_F_REQUEST = 0x01
NLM_F_ACK = 0x04
NLMSG_ERROR = 2

# HT|VHT|HE preambles (NL80211_PREAMBLE_* bits 1,2,4)
_PREAMBLES = (1 << 1) | (1 << 2) | (1 << 4)
# bandwidths, NL80211_CHAN_WIDTH_* bits: 20=1, 40=2, 80=3, 160=5, 320=13.
# (320 also needs an EHT/6GHz-capable radio to actually be requested.)
_BANDWIDTHS = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5) | (1 << 13)


def _nla(atype, payload):
    """One netlink attribute (TLV), padded to a 4-byte boundary."""
    pad = (4 - len(payload) % 4) % 4
    return struct.pack('HH', len(payload) + 4, atype) + payload + b'\x00' * pad


def _u32(atype, value):
    return _nla(atype, struct.pack('I', value))


def _flag(atype):
    return _nla(atype, b'')


def _nest(atype, *attrs):
    return _nla(atype | NLA_F_NESTED, b''.join(attrs))


def _pmsr_support():
    """HWSIM_ATTR_PMSR_SUPPORT -> TYPE_CAPA -> FTM: a default FTM capability."""
    ftm = _nest(PMSR_TYPE_FTM,
                _u32(FTM_CAPA_PREAMBLES, _PREAMBLES),
                _u32(FTM_CAPA_BANDWIDTHS, _BANDWIDTHS),
                _flag(FTM_CAPA_ASAP),
                _flag(FTM_CAPA_NON_ASAP))
    return _nest(HWSIM_ATTR_PMSR_SUPPORT,
                 _u32(PMSR_ATTR_MAX_PEERS, 16),
                 _nest(PMSR_ATTR_TYPE_CAPA, ftm))


def _request(sock, family_id, cmd, payload, seq, ack):
    flags = NLM_F_REQUEST | (NLM_F_ACK if ack else 0)
    genl = struct.pack('BBH', cmd, 1, 0) + payload
    msg = struct.pack('IHHII', 16 + len(genl), family_id, flags, seq, 0) + genl
    sock.send(msg)
    return sock.recv(8192)


def _resolve_family(sock, name):
    reply = _request(sock, GENL_ID_CTRL, CTRL_CMD_GETFAMILY,
                     _nla(CTRL_ATTR_FAMILY_NAME, name.encode() + b'\x00'),
                     seq=1, ack=False)
    attrs, off = reply[20:], 0          # skip nlmsghdr(16) + genlmsghdr(4)
    while off + 4 <= len(attrs):
        alen, atype = struct.unpack_from('HH', attrs, off)
        if atype == CTRL_ATTR_FAMILY_ID:
            return struct.unpack_from('H', attrs, off + 4)[0]
        off += (alen + 3) & ~3
    raise OSError('generic netlink family %r not found' % name)


def create_ftm_radio(name):
    """Create an FTM/PMSR-capable hwsim radio named ``name`` (stock module)."""
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    try:
        sock.settimeout(5)
        sock.bind((0, 0))
        family = _resolve_family(sock, 'MAC80211_HWSIM')
        payload = _nla(HWSIM_ATTR_RADIO_NAME,
                       name.encode() + b'\x00') + _pmsr_support()
        reply = _request(sock, family, HWSIM_CMD_NEW_RADIO, payload,
                         seq=2, ack=True)
        msg_type = struct.unpack_from('HH', reply, 4)[1]
        if msg_type == NLMSG_ERROR:
            err = struct.unpack_from('i', reply, 16)[0]
            if err < 0:
                raise OSError(-err, 'NEW_RADIO(%s) failed' % name)
    finally:
        sock.close()


if __name__ == '__main__':          # manual test: python3 -m mn_wifi.hwsim_pmsr <name>
    import sys
    create_ftm_radio(sys.argv[1] if len(sys.argv) > 1 else 'phyrewalltest0')
    print('created FTM-capable radio')
