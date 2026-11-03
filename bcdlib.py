"""bcdlib - read/write Windows BCD stores (registry hives) from Linux via libhivex.

Shared by `bcdedit` and `bcdboot`. Layout of a store:
  \\Description\\{KeyName,System}      \\Objects\\{guid}\\Description\\Type (dword)
  \\Objects\\{guid}\\Elements\\<8hex>\\Element  (REG_SZ / REG_MULTI_SZ / REG_BINARY)
"""
import ctypes, ctypes.util, os, re, struct, uuid, subprocess

REG_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ = 1, 3, 4, 7

# ---------------------------------------------------------------- libhivex
_lib = ctypes.CDLL(ctypes.util.find_library("hivex") or "libhivex.so.0")
_libc = ctypes.CDLL(None)
_libc.free.argtypes = [ctypes.c_void_p]
_sz = ctypes.c_size_t
_lib.hivex_open.restype = ctypes.c_void_p
_lib.hivex_open.argtypes = [ctypes.c_char_p, ctypes.c_int]
_lib.hivex_root.restype = _sz;            _lib.hivex_root.argtypes = [ctypes.c_void_p]
_lib.hivex_node_children.restype = ctypes.POINTER(_sz)
_lib.hivex_node_children.argtypes = [ctypes.c_void_p, _sz]
_lib.hivex_node_values.restype = ctypes.POINTER(_sz)
_lib.hivex_node_values.argtypes = [ctypes.c_void_p, _sz]
_lib.hivex_node_name.restype = ctypes.c_void_p
_lib.hivex_node_name.argtypes = [ctypes.c_void_p, _sz]
_lib.hivex_node_get_child.restype = _sz
_lib.hivex_node_get_child.argtypes = [ctypes.c_void_p, _sz, ctypes.c_char_p]
_lib.hivex_node_add_child.restype = _sz
_lib.hivex_node_add_child.argtypes = [ctypes.c_void_p, _sz, ctypes.c_char_p]
_lib.hivex_node_delete_child.argtypes = [ctypes.c_void_p, _sz]
_lib.hivex_value_key.restype = ctypes.c_void_p
_lib.hivex_value_key.argtypes = [ctypes.c_void_p, _sz]
_lib.hivex_value_value.restype = ctypes.c_void_p
_lib.hivex_value_value.argtypes = [ctypes.c_void_p, _sz, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(_sz)]
_lib.hivex_commit.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
_lib.hivex_close.argtypes = [ctypes.c_void_p]


class _SetValue(ctypes.Structure):
    _fields_ = [("key", ctypes.c_char_p), ("t", ctypes.c_int),
                ("len", _sz), ("value", ctypes.c_char_p)]
_lib.hivex_node_set_value.argtypes = [ctypes.c_void_p, _sz, ctypes.POINTER(_SetValue), ctypes.c_int]


class Hive:
    def __init__(self, path, write=False):
        self.path = path
        self.h = _lib.hivex_open(path.encode(), 4 if write else 0)
        if not self.h:
            raise OSError("cannot open hive %s" % path)
        self.write = write

    def root(self): return _lib.hivex_root(self.h)

    @staticmethod
    def _take(p):
        s = ctypes.string_at(p).decode("utf-8", "replace"); _libc.free(p); return s

    @staticmethod
    def _arr(p):
        out, i = [], 0
        while p[i]: out.append(p[i]); i += 1
        _libc.free(ctypes.cast(p, ctypes.c_void_p)); return out

    def children(self, n): return self._arr(_lib.hivex_node_children(self.h, n))
    def name(self, n): return self._take(_lib.hivex_node_name(self.h, n))
    def child(self, n, name):
        """Case-insensitive child lookup; 0 when missing."""
        c = _lib.hivex_node_get_child(self.h, n, name.encode())
        if c: return c
        for k in self.children(n):
            if self.name(k).lower() == name.lower(): return k
        return 0
    def path(self_, p, start=None):
        n = start or self_.root()
        for part in [x for x in re.split(r"[\\/]", p) if x]:
            n = self_.child(n, part)
            if not n: return 0
        return n
    def add_child(self, n, name):
        r = _lib.hivex_node_add_child(self.h, n, name.encode())
        if not r: raise OSError("add_child %s failed" % name)
        return r
    def ensure(self, n, name): return self.child(n, name) or self.add_child(n, name)
    def delete(self, n):
        if _lib.hivex_node_delete_child(self.h, n): raise OSError("delete failed")
    def values(self, n):
        out = {}
        for v in self._arr(_lib.hivex_node_values(self.h, n)):
            k = self._take(_lib.hivex_value_key(self.h, v))
            ln, t = _sz(), ctypes.c_int()
            p = _lib.hivex_value_value(self.h, v, ctypes.byref(t), ctypes.byref(ln))
            out[k] = (t.value, ctypes.string_at(p, ln.value)); _libc.free(p)
        return out
    def set(self, n, key, typ, data):
        buf = ctypes.create_string_buffer(data, len(data))
        sv = _SetValue(key.encode(), typ, len(data), ctypes.cast(buf, ctypes.c_char_p))
        if _lib.hivex_node_set_value(self.h, n, ctypes.byref(sv), 0): raise OSError("set_value failed")
    def commit(self):
        if _lib.hivex_commit(self.h, None, 0): raise OSError("commit failed")
    def close(self):
        if self.h: _lib.hivex_close(self.h); self.h = None
    def __enter__(self): return self
    def __exit__(self, *a): self.close()


# ---------------------------------------------------------------- element encoding
def u16z(s): return s.encode("utf-16-le") + b"\0\0"
def from_u16z(b): return b.decode("utf-16-le", "replace").rstrip("\0")
def multi(strs): return b"".join(u16z(s) for s in strs) + b"\0\0"
def from_multi(b): return [x for x in b.decode("utf-16-le", "replace").split("\0") if x]

FMT = {1: "device", 2: "string", 3: "object", 4: "objectlist", 5: "integer", 6: "boolean", 7: "intlist"}
def fmt_of(eid): return FMT.get((eid >> 24) & 0xF, "raw")

def norm_guid(g):
    g = g.strip().strip("{}").lower()
    return "{" + g + "}"

WELL_KNOWN = {
    "{bootmgr}": "{9dea862c-5cdd-4e70-acc1-f32b344d4795}",
    "{memdiag}": "{b2721d73-1db4-4c62-bf78-c548a880142d}",
    "{ntldr}": "{466f5a88-0af2-4f76-9038-095b170dc21c}",
    "{badmemory}": "{5189b25c-5558-4bf2-bca4-289b11bd29e2}",
    "{dbgsettings}": "{4636856e-540f-4170-a130-a84776f4c654}",
    "{emssettings}": "{0ce4991b-e6b3-4b16-b23c-5e0d9250e5d9}",
    "{globalsettings}": "{7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e}",
    "{resumeloadersettings}": "{1afa9c49-16ab-4a5c-901b-212802da9460}",
    "{hypervisorsettings}": "{7ff607e0-4395-11db-b0de-0800200c9a66}",
    "{bootloadersettings}": "{6efb52bf-1766-41db-a6b3-0ee5eff72bd7}",
    "{ramdiskoptions}": "{ae5534e0-a924-466c-b836-758539a3ee3a}",
    "{legacy}": "{466f5a88-0af2-4f76-9038-095b170dc21c}",
}
REVERSE_KNOWN = {v: k for k, v in WELL_KNOWN.items() if k != "{legacy}"}

# best-effort friendly names (MS BCD WMI element docs); raw 8-hex ids always work too
LIB = {
 "device":0x11000001,"path":0x12000002,"description":0x12000004,"locale":0x12000005,
 "inherit":0x14000006,"truncatememory":0x15000007,"recoverysequence":0x14000008,
 "recoveryenabled":0x16000009,"badmemorylist":0x1700000a,"badmemoryaccess":0x1600000b,
 "firstmegabytepolicy":0x1500000c,"relocatephysical":0x1500000d,"avoidlowmemory":0x1500000e,
 "debug":0x16000010,"debugtype":0x15000011,"debugaddress":0x15000012,"debugport":0x15000013,
 "baudrate":0x15000014,"channel":0x15000015,"targetname":0x12000016,
 "noumex":0x16000017,"debugstart":0x15000018,"busparams":0x12000019,
 "bootems":0x16000020,"emsport":0x15000022,"emsbaudrate":0x15000023,
 "loadoptions":0x12000030,"displaybootmenu":0x16000040,"noerrordisplay":0x16000041,
 "bootlogo":0x16000046,"nointegritychecks":0x16000048,"testsigning":0x16000049,
 "fontpath":0x1200004a,"isolatedcontext":0x16000060,"graphicsresolution":0x15000052,
 "restartonfailure":0x16000053,"highestmode":0x16000054,"allowedinmemorysettings":0x17000077,
}
BOOTMGR = {
 "displayorder":0x24000001,"bootsequence":0x24000002,"default":0x23000003,
 "timeout":0x25000004,"resume":0x26000005,"resumeobject":0x23000006,
 "toolsdisplayorder":0x24000010,"displaybootmenu":0x26000020,"noerrordisplay":0x26000021,
 "bcddevice":0x21000022,"bcdfilepath":0x22000023,
}
OSLOADER = {
 "osdevice":0x21000001,"systemroot":0x22000002,"resumeobject":0x23000003,
 "detecthal":0x26000010,"kernel":0x22000011,"hal":0x22000012,"dbgtransport":0x22000013,
 "nx":0x25000020,"pae":0x25000021,"winpe":0x26000022,"nocrashautoreboot":0x26000024,
 "lastknowngood":0x26000025,"onecpu":0x26000060,"numproc":0x25000061,
 "safeboot":0x25000080,"safebootalternateshell":0x26000081,"bootlog":0x26000090,
 "sos":0x26000091,"novesa":0x26000042,"kerneldebug":0x260000a0,"halbreakpoint":0x260000a1,
 "useplatformclock":0x260000a2,"ems":0x260000b0,"bootmenupolicy":0x250000c2,
 "bootstatuspolicy":0x250000e0,"hypervisorlaunchtype":0x250000f0,
 "hypervisordebugtype":0x250000f3,"hypervisordebugport":0x250000f4,"hypervisorbaudrate":0x250000f5,
}
RESUME = {
 "device":0x11000001,"filedevice":0x21000001,"filepath":0x22000002,
 "customsettings":0x17000077,"pae":0x25000021,"debugoptionenabled":0x26000004
}
TYPES = {"bootmgr":0x10100002,"osloader":0x10200003,"resume":0x10200004,"memdiag":0x10200005,
         "inherit":0x20200003,"device":0x30000000}

def kind_of_type(t):
    return {0x10100002:"bootmgr",0x10200003:"osloader",0x10200004:"resume",0x10200005:"memdiag"}.get(t,"other")

def name_table(kind):
    t = dict(LIB)
    t.update({"bootmgr":BOOTMGR,"osloader":OSLOADER,"resume":RESUME}.get(kind, {}))
    return t

def element_id(name, kind):
    n = name.lower().lstrip("/")
    if re.fullmatch(r"[0-9a-f]{8}", n): return int(n, 16)
    if re.fullmatch(r"0x[0-9a-f]{1,8}", n): return int(n, 16)
    tab = name_table(kind)
    if n in tab: return tab[n]
    raise KeyError("unknown element name: %s" % name)

def element_name(eid, kind):
    for k, v in name_table(kind).items():
        if v == eid: return k
    return "%08x" % eid

def encode_element(eid, text):
    """Encode a command-line value for element id (device blobs aren't settable here)."""
    f = fmt_of(eid)
    if f == "string": return REG_SZ, u16z(text)
    if f == "object": return REG_SZ, u16z(resolve_guid(text))
    if f == "objectlist":
        return REG_MULTI_SZ, multi([resolve_guid(x) for x in text.replace(",", " ").split()])
    if f == "integer": return REG_BINARY, struct.pack("<Q", int(text, 0))
    if f == "boolean":
        v = text.lower() in ("1", "on", "yes", "true", "enable", "enabled")
        if text.lower() not in ("1","on","yes","true","enable","enabled","0","off","no","false","disable","disabled"):
            raise ValueError("boolean expected (on/off): %s" % text)
        return REG_BINARY, bytes([v])
    if f == "intlist":
        return REG_BINARY, b"".join(struct.pack("<Q", int(x, 0)) for x in text.replace(",", " ").split())
    raise ValueError("element %08x has format %s: cannot be set from text" % (eid, f))

def resolve_guid(s):
    s = s.strip()
    k = s.lower()
    if k in WELL_KNOWN: return WELL_KNOWN[k]
    if k in ("{default}", "{current}"): return k
    return norm_guid(s)


# ---------------------------------------------------------------- device blobs
def guid_bytes(g): return uuid.UUID(g.strip("{}")).bytes_le

def device_partition_gpt(disk_guid, part_guid):
    return (b"\0" * 16 + struct.pack("<II", 6, 0) + struct.pack("<II", 0x48, 0) +
            guid_bytes(part_guid) + b"\0" * 4 + b"\x00\0\0\0" + guid_bytes(disk_guid) + b"\0" * 16)

def device_partition_mbr(disk_sig, byte_offset):
    return (b"\0" * 16 + struct.pack("<II", 6, 0) + struct.pack("<II", 0x48, 0) +
            struct.pack("<Q", byte_offset) + b"\0" * 8 + b"\0" * 4 + b"\x01\0\0\0" +
            struct.pack("<I", disk_sig) + b"\0" * 12 + b"\0" * 16)

def _run(*a):
    return subprocess.run(a, capture_output=True, text=True, check=True).stdout.strip()

def device_for_path(path):
    """Device blob for whichever block device backs `path` (GPT or MBR)."""
    part = _run("findmnt", "-nT", path, "-o", "SOURCE").split("[")[0]
    if not part.startswith("/dev/"): raise RuntimeError("%s is not on a block device (%s)" % (path, part))
    return device_for_blockdev(part)

def device_for_blockdev(part):
    row = _run("lsblk", "-rno", "PKNAME,PARTUUID", part).split("\n")[0].split(" ")
    pk, puuid = row[0], (row[1] if len(row) > 1 else "")
    disk = "/dev/" + pk
    drow = _run("lsblk", "-dno", "PTTYPE,PTUUID", disk).split()
    ptt, ptuuid = drow[0], drow[1]
    if ptt == "gpt":
        return device_partition_gpt(ptuuid, puuid)
    if ptt == "dos":
        base = os.path.basename(part)
        start = int(open("/sys/class/block/%s/start" % base).read())
        ss = int(open("/sys/block/%s/queue/logical_block_size" % pk).read())
        return device_partition_mbr(int(ptuuid, 16), start * ss)
    raise RuntimeError("unsupported partition table: " + ptt)

def parse_device_spec(spec):
    """gpt:<diskguid>:<partguid> | mbr:<hexsig>:<byteoffset> | /dev/xxx"""
    if spec.startswith("/dev/"): return device_for_blockdev(spec)
    k, a, b = spec.split(":")
    if k == "gpt": return device_partition_gpt(a, b)
    if k == "mbr": return device_partition_mbr(int(a, 16), int(b, 0))
    raise ValueError("bad device spec " + spec)

def describe_device(b):
    if len(b) >= 88 and struct.unpack_from("<I", b, 16)[0] == 6:
        if b[52] == 0:
            return "partition(gpt disk=%s part=%s)" % (uuid.UUID(bytes_le=b[56:72]), uuid.UUID(bytes_le=b[32:48]))
        return "partition(mbr sig=%08x offset=%d)" % (struct.unpack_from("<I", b, 56)[0], struct.unpack_from("<Q", b, 32)[0])
    return "binary(%d bytes)" % len(b)


# ---------------------------------------------------------------- store
class Store:
    def __init__(self, path, write=False):
        self.hive = Hive(path, write)
        h = self.hive
        r = h.root()
        self.objects = h.child(r, "Objects")
        self.desc = h.child(r, "Description")
        if not self.objects: raise ValueError("%s is not a BCD store" % path)

    def close(self): self.hive.close()
    def commit(self): self.hive.commit()
    def __enter__(self): return self
    def __exit__(self, *a): self.close()

    def guids(self): return [self.hive.name(n) for n in self.hive.children(self.objects)]
    def node(self, guid): return self.hive.child(self.objects, guid)

    def type_of(self, guid):
        n = self.node(guid)
        d = self.hive.child(n, "Description")
        v = self.hive.values(d).get("Type")
        return struct.unpack("<I", v[1])[0] if v else 0

    def elements(self, guid):
        """{eid: (regtype, bytes)}"""
        h = self.hive
        e = h.child(self.node(guid), "Elements")
        out = {}
        for c in (h.children(e) if e else []):
            nm = h.name(c)
            v = h.values(c).get("Element")
            if v: out[int(nm, 16)] = v
        return out

    def get(self, guid, eid):
        return self.elements(guid).get(eid)

    def set_raw(self, guid, eid, typ, data):
        h = self.hive
        e = h.ensure(self.node(guid), "Elements")
        n = h.ensure(e, "%08x" % eid)
        h.set(n, "Element", typ, data)

    def delete_element(self, guid, eid):
        h = self.hive
        e = h.child(self.node(guid), "Elements")
        c = h.child(e, "%08x" % eid) if e else 0
        if not c: return False
        h.delete(c); return True

    def create_object(self, guid, objtype):
        h = self.hive
        if self.node(guid): raise ValueError("object %s already exists" % guid)
        n = h.add_child(self.objects, guid)
        d = h.add_child(n, "Description")
        h.set(d, "Type", REG_DWORD, struct.pack("<I", objtype))
        h.add_child(n, "Elements")
        return n

    def delete_object(self, guid):
        self.hive.delete(self.node(guid))

    def set_description_value(self, key, typ, data):
        self.hive.set(self.desc, key, typ, data)

    # -- helpers on well-known lists
    def objlist(self, guid, eid):
        v = self.get(guid, eid)
        return from_multi(v[1]) if v else []

    def set_objlist(self, guid, eid, lst):
        self.set_raw(guid, eid, REG_MULTI_SZ, multi(lst))

    def resolve(self, ident):
        """map {default}/{current}/aliases to a guid present in the store"""
        k = ident.lower()
        if k in ("{default}", "{current}"):
            v = self.get(WELL_KNOWN["{bootmgr}"], BOOTMGR["default"])
            if not v: raise KeyError("no default entry")
            return from_u16z(v[1]).lower()
        g = resolve_guid(ident)
        if not self.node(g):
            raise KeyError("object not found: " + ident)
        return g


def new_guid(): return "{%s}" % uuid.uuid4()
BOOTMGR_GUID = WELL_KNOWN["{bootmgr}"]
MEMDIAG_GUID = WELL_KNOWN["{memdiag}"]
