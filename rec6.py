#!/usr/bin/env python3
# rec5.py - InnoDB dictionary + carved page recovery helper (v5)
# ASCII only: this file travels through GitHub raw and a VNC console.
#
# WHY rec4 PRINTED 0 RECORDS
#   SYS_TABLES record (REDUNDANT), offsets relative to the END of NAME:
#     +0  DB_TRX_ID (6)
#     +6  DB_ROLL_PTR(7)
#     +13 ID        (8)   <- rec4 read it at +8, i.e. inside DB_ROLL_PTR -> 0
#     +21 N_COLS    (4)   bit31 = COMPACT flag, must be masked off
#     +25 TYPE      (4)
#     +29 MIX_ID    (8)   always 0 -> strong validator
#     +37 MIX_LEN   (4)
#     +41 SPACE     (4)
#   fixed tail = 6+7+8+4+4+8+4+4 = 45 bytes, matching the hex dump of
#   mysql/innodb_table_stats (N_COLS 6, TYPE 33, MIX_ID 0, MIX_LEN 80, SPACE 1).
#   v5 trusts nothing: it calibrates the offset against known control records.
#
# SYS_INDEXES record, offsets relative to the START of TABLE_ID:
#   +0 TABLE_ID(8) +8 ID(8) +16 DB_TRX_ID(6) +22 DB_ROLL_PTR(7)
#   +29 NAME(var) then N_FIELDS(4) TYPE(4) SPACE(4) PAGE_NO(4)
#
# Page header: +4 page_no +16 LSN +24 type(17855) +34 space +54 n_recs
#              +64 level(0=leaf) +66 index_id
#
# MODES
#   rec5.py probe [dict-file ...]
#   rec5.py map   [dict-file ...] [--db foxcoin_app] [--all]
#   rec5.py inv   [pages-dir] [--top 40] [--space N]
#   rec5.py plan  [--db foxcoin_app] [--dict F] [--pages D]
#   rec5.py auto  [--db foxcoin_app] [--out DIR] [--decode]
#   rec5.py pull  <space> <index> <out.page> [pages-dir]
import collections
import glob
import os
import re
import subprocess
import sys

PG = 16384
DEF_PAGES = "/mnt/recovery/pages4/FIL_PAGE_INDEX"
DEF_DICT = "/mnt/main/var/lib/mysql/ibdata1"
DEF_OUT = "/mnt/recovery/rec5out"
DEF_DEFS = "/mnt/recovery/defs"
IPARSE = "/mnt/recovery/iparse.py"

CTRL = [
    ("mysql/innodb_table_stats", 14, 1),
    ("mysql/innodb_index_stats", 15, 2),
    ("mysql/transaction_registry", 16, 3),
    ("mysql/gtid_slave_pos", 17, 4),
    ("phpmyadmin/pma__bookmark", 18, 5),
    ("phpmyadmin/pma__central_columns", 34, 21),
]

NAME_RE = re.compile(rb"[a-z0-9_]{2,30}/[a-zA-Z0-9_@$]{2,60}")
NAME_FULL = re.compile(rb"\A[a-z0-9_]{2,30}/[a-zA-Z0-9_@$]{2,60}\Z")
ID_OFF, NC_OFF, TP_OFF, MX_OFF, ML_OFF, SP_OFF = 13, 21, 25, 29, 37, 41


def u(b, o, n):
    if o < 0 or o + n > len(b):
        return -1
    return int.from_bytes(b[o:o + n], "big")


def load(path):
    with open(path, "rb") as f:
        return f.read()


def tail(b, p, d):
    tid = u(b, p + ID_OFF + d, 8)
    nc = u(b, p + NC_OFF + d, 4)
    tp = u(b, p + TP_OFF + d, 4)
    mx = u(b, p + MX_OFF + d, 8)
    ml = u(b, p + ML_OFF + d, 4)
    sp = u(b, p + SP_OFF + d, 4)
    if min(tid, nc, tp, mx, ml, sp) < 0:
        return None
    ncols = nc & 0x7FFFFFFF
    if not 0 < tid < 10 ** 7:
        return None
    if not 0 < ncols <= 1017:
        return None
    if not 0 < tp < 1 << 24:
        return None
    if mx != 0:
        return None
    if ml >= 1 << 20:
        return None
    if sp >= 1 << 24:
        return None
    return {"tid": tid, "ncols": ncols, "type": tp, "mixlen": ml, "space": sp,
            "compact": bool(nc & 0x80000000)}


def calibrate(b):
    best_d, best_hits = 0, []
    for d in range(-8, 17):
        hits = []
        for nm, tid, sp in CTRL:
            n = nm.encode()
            st = 0
            while True:
                i = b.find(n, st)
                if i < 0:
                    break
                st = i + 1
                e = i + len(n)
                if u(b, e + ID_OFF + d, 8) == tid and u(b, e + SP_OFF + d, 4) == sp:
                    hits.append((nm, i, tail(b, e, d)))
                    break
        if len(hits) > len(best_hits):
            best_d, best_hits = d, hits
    return best_d, best_hits


def scan_tables(b, d):
    out = collections.Counter()
    for m in NAME_RE.finditer(b):
        s, e = m.start(), m.end()
        for p in range(e, s + 4, -1):
            nm = b[s:p]
            if not NAME_FULL.match(nm):
                continue
            r = tail(b, p, d)
            if r:
                name = nm.decode("ascii", "ignore")
                if "/fk_" in name:
                    break
                out[(name, r["tid"], r["space"], r["ncols"])] += 1
                break
    return out


def scan_indexes(b, space_of):
    out = collections.defaultdict(set)
    for tid, sp in space_of.items():
        pat = tid.to_bytes(8, "big")
        st = 0
        while True:
            q = b.find(pat, st)
            if q < 0:
                break
            st = q + 1
            iid = u(b, q + 8, 8)
            if not 0 < iid < 10 ** 9:
                continue
            base = q + 29
            for L in range(1, 41):
                if base + L + 16 > len(b):
                    break
                c = b[base + L - 1]
                ok = (48 <= c <= 57) or (65 <= c <= 90) or (97 <= c <= 122) or c in (95, 36)
                if not ok:
                    break
                if L < 3:
                    continue
                if u(b, base + L + 8, 4) == sp:
                    root = u(b, base + L + 12, 4)
                    if 0 < root < 10 ** 7:
                        nm = b[base:base + L].decode("ascii", "ignore")
                        out[tid].add((iid, sp, root, nm))
                        break
    return out


def dictionary(paths, db=None):
    tabs = collections.Counter()
    idx = collections.defaultdict(set)
    info = []
    for path in paths:
        if not os.path.exists(path):
            info.append("# MISSING %s" % path)
            continue
        b = load(path)
        d, hits = calibrate(b)
        info.append("# %s (%d bytes) calib delta=%d controls=%d/%d"
                    % (path, len(b), d, len(hits), len(CTRL)))
        t = scan_tables(b, d)
        tabs.update(t)
        space_of = {}
        for (name, tid, space, ncols) in t:
            if db and (db + "/") not in name:
                continue
            space_of[tid] = space
        for tid, rows in scan_indexes(b, space_of).items():
            idx[tid] |= rows
    return tabs, idx, info


def clean(name, db):
    if db and (db + "/") in name:
        return db + "/" + name.split(db + "/", 1)[1]
    return name


def page_iter(path):
    b = load(path)
    for o in range(0, len(b) - PG + 1, PG):
        yield o, b[o:o + PG]


def scan_pages(pages_dir, wanted=None):
    stats = collections.defaultdict(lambda: [0, 0, 0])
    loc = collections.defaultdict(dict)
    files = sorted(glob.glob(os.path.join(pages_dir, "*.page")))
    for path in files:
        for off, p in page_iter(path):
            if u(p, 24, 2) != 17855:
                continue
            key = (u(p, 34, 4), u(p, 66, 8))
            leaf = u(p, 64, 2) == 0
            s = stats[key]
            s[0] += 1
            if leaf:
                s[1] += 1
                s[2] += u(p, 54, 2)
            if wanted is not None and key not in wanted:
                continue
            no, lsn = u(p, 4, 4), u(p, 16, 8)
            cur = loc[key].get(no)
            if cur is None or cur[0] < lsn:
                loc[key][no] = (lsn, path, off)
    return stats, loc, len(files)


def write_group(loc_group, dest):
    handles = {}
    leaf = recs = 0
    try:
        with open(dest, "wb") as out:
            for no in sorted(loc_group):
                lsn, path, off = loc_group[no]
                h = handles.get(path)
                if h is None:
                    h = handles[path] = open(path, "rb")
                h.seek(off)
                p = h.read(PG)
                out.write(p)
                if u(p, 64, 2) == 0:
                    leaf += 1
                    recs += u(p, 54, 2)
    finally:
        for h in handles.values():
            h.close()
    return len(loc_group), leaf, recs


def split_args(rest):
    pos, opt = [], {}
    i = 0
    while i < len(rest):
        a = rest[i]
        if a.startswith("--"):
            k = a[2:]
            if "=" in k:
                k, v = k.split("=", 1)
            elif i + 1 < len(rest) and not rest[i + 1].startswith("--"):
                i += 1
                v = rest[i]
            else:
                v = "1"
            opt[k] = v
        else:
            pos.append(a)
        i += 1
    return pos, opt


def do_probe(pos, opt):
    paths = pos or [DEF_DICT]
    for path in paths:
        if not os.path.exists(path):
            print("MISSING %s" % path)
            continue
        b = load(path)
        d, hits = calibrate(b)
        print("file %s  %d bytes" % (path, len(b)))
        print("delta %d  controls matched %d/%d" % (d, len(hits), len(CTRL)))
        for nm, off, r in hits[:4]:
            print("  %-30s @%d id=%s ncols=%s type=%s mixlen=%s space=%s"
                  % (nm, off, r["tid"], r["ncols"], r["type"], r["mixlen"], r["space"]))
        t = scan_tables(b, d)
        print("  SYS_TABLES rows %d distinct %d" % (sum(t.values()), len(t)))
        print("  foxcoin rows %d" % sum(1 for (n, _, _, _) in t if "foxcoin" in n))
        if not hits:
            print("  NOTE: no control matched, offsets unverified")


def do_map(pos, opt):
    paths = pos or [DEF_DICT]
    db = None if opt.get("all") else opt.get("db", "foxcoin_app")
    tabs, idx, info = dictionary(paths, db)
    for line in info:
        print(line)
    print("# table\ttable_id\tspace\tncols\tindex_id\troot\tindex")
    seen = set()
    n = 0
    for (name, tid, space, ncols) in sorted(tabs):
        if db and (db + "/") not in name:
            continue
        nm = clean(name, db)
        if (nm, tid, space) in seen:
            continue
        seen.add((nm, tid, space))
        n += 1
        rows = sorted(r for r in idx.get(tid, ()) if r[1] == space)
        if rows:
            for iid, sp, root, iname in rows:
                print("%s\t%d\t%d\t%d\t%d\t%d\t%s" % (nm, tid, sp, ncols, iid, root, iname))
        else:
            print("%s\t%d\t%d\t%d\t-\t-\t-" % (nm, tid, space, ncols))
    print("# tables listed: %d" % n)


def do_inv(pos, opt):
    pages_dir = pos[0] if pos else DEF_PAGES
    top = int(opt.get("top", 40))
    only = int(opt["space"]) if "space" in opt else None
    stats, _, nfiles = scan_pages(pages_dir, wanted=set())
    print("# dir %s files %d groups %d" % (pages_dir, nfiles, len(stats)))
    print("# space\tindex_id\tpages\tleaf\trecs")
    rows = sorted(stats.items(), key=lambda kv: -kv[1][0])
    shown = 0
    for (sp, ix), (n, leaf, recs) in rows:
        if only is not None and sp != only:
            continue
        print("%d\t%d\t%d\t%d\t%d" % (sp, ix, n, leaf, recs))
        shown += 1
        if shown >= top:
            break


def build_plan(opt):
    db = opt.get("db", "foxcoin_app")
    dict_paths = [opt.get("dict", DEF_DICT)]
    if opt.get("dict2"):
        dict_paths.append(opt["dict2"])
    pages_dir = opt.get("pages", DEF_PAGES)
    tabs, idx, info = dictionary(dict_paths, db)
    tables = {}
    for (name, tid, space, ncols) in tabs:
        if (db + "/") not in name:
            continue
        nm = clean(name, db).split("/", 1)[1]
        cur = tables.setdefault(nm, {"tid": tid, "space": space, "ncols": ncols, "idx": set()})
        cur["idx"] |= {r for r in idx.get(tid, ()) if r[1] == space}
    stats, loc, nfiles = scan_pages(pages_dir, wanted=None)
    groups = collections.defaultdict(list)
    for (sp, ix), (n, leaf, recs) in stats.items():
        groups[sp].append((ix, n, leaf, recs))
    return db, tables, groups, stats, loc, info, nfiles, pages_dir


def do_plan(pos, opt):
    db, tables, groups, stats, loc, info, nfiles, pdir = build_plan(opt)
    for line in info:
        print(line)
    print("# pages dir %s files %d groups %d" % (pdir, nfiles, len(stats)))
    print("# table\tspace\tncols\tindex_id\tpages\tleaf\trecs\tsrc")
    claimed = set()
    for nm in sorted(tables):
        t = tables[nm]
        sp = t["space"]
        dict_idx = {r[0] for r in t["idx"]}
        rows = sorted(groups.get(sp, []), key=lambda r: -r[2])
        if not rows:
            print("%s\t%d\t%d\t-\t0\t0\t0\tNOPAGES" % (nm, sp, t["ncols"]))
            continue
        for ix, n, leaf, recs in rows:
            claimed.add((sp, ix))
            src = "dict" if ix in dict_idx else "space"
            print("%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s" % (nm, sp, t["ncols"], ix, n, leaf, recs, src))
    print("# tables %d" % len(tables))
    rest = sorted(((k, v) for k, v in stats.items() if k not in claimed),
                  key=lambda kv: -kv[1][1])[:15]
    print("# unclaimed (space index pages leaf recs)")
    for (sp, ix), (n, leaf, recs) in rest:
        print("?\t%d\t%d\t%d\t%d\t%d" % (sp, ix, n, leaf, recs))


def do_auto(pos, opt):
    db, tables, groups, stats, loc, info, nfiles, pdir = build_plan(opt)
    outdir = opt.get("out", DEF_OUT)
    os.makedirs(outdir, exist_ok=True)
    for line in info:
        print(line)
    print("# pages dir %s files %d" % (pdir, nfiles))
    print("# table\tspace\tindex\tpages\tleaf\trecs\tfile")
    made = []
    for nm in sorted(tables):
        t = tables[nm]
        sp = t["space"]
        rows = sorted(groups.get(sp, []), key=lambda r: -r[2])
        if not rows:
            print("%s\t%d\t-\t0\t0\t0\tNOPAGES" % (nm, sp))
            continue
        for ix, n, leaf, recs in rows[:3]:
            dest = os.path.join(outdir, "%s.sp%d.ix%d.page" % (nm, sp, ix))
            got, gleaf, grecs = write_group(loc[(sp, ix)], dest)
            print("%s\t%d\t%d\t%d\t%d\t%d\t%s"
                  % (nm, sp, ix, got, gleaf, grecs, os.path.basename(dest)))
            made.append((nm, gleaf, grecs, dest))
    print("# written %d files to %s" % (len(made), outdir))
    if opt.get("decode"):
        defs = opt.get("defs", DEF_DEFS)
        iparse = opt.get("iparse", IPARSE)
        print("# decode")
        best = {}
        for nm, leaf, recs, dest in made:
            if leaf and (nm not in best or best[nm][0] < leaf):
                best[nm] = (leaf, dest)
        for nm in sorted(best):
            d = os.path.join(defs, nm + ".sql")
            if not os.path.exists(d):
                print("%s\tno def %s" % (nm, d))
                continue
            tsv = os.path.join(outdir, nm + ".tsv")
            with open(tsv, "wb") as fh:
                r = subprocess.run([sys.executable, iparse, d, best[nm][1]],
                                   stdout=fh, stderr=subprocess.PIPE)
            rows = sum(1 for _ in open(tsv, "rb"))
            err = r.stderr.decode("utf-8", "ignore").strip().splitlines()
            print("%s\trows=%d\t%s" % (nm, rows, err[-1][:60] if err else "ok"))


def do_pull(pos, opt):
    space, index, dest = int(pos[0]), int(pos[1]), pos[2]
    pages_dir = pos[3] if len(pos) > 3 else DEF_PAGES
    _, loc, _ = scan_pages(pages_dir, wanted={(space, index)})
    got, leaf, recs = write_group(loc[(space, index)], dest)
    print("pages=%d leaf=%d recs=%d -> %s" % (got, leaf, recs, dest))



"""Prototype: rebuild column definitions from SYS_COLUMNS garbage records.

SYS_COLUMNS record (REDUNDANT), offsets from the start of TABLE_ID:
  +0  TABLE_ID(8)  +8 POS(4)  +12 DB_TRX_ID(6)  +18 DB_ROLL_PTR(7)
  +25 NAME(var) then MTYPE(4) PRTYPE(4) LEN(4) PREC(4)
"""
import collections
import re

MTYPE = {1: "VARCHAR", 2: "CHAR", 3: "FIXBINARY", 4: "BINARY", 5: "BLOB",
         6: "INT", 7: "SYS_CHILD", 8: "SYS", 9: "FLOAT", 10: "DOUBLE",
         11: "DECIMAL", 12: "VARMYSQL", 13: "MYSQL", 14: "GEOMETRY"}

MYSQL = {0: "DECIMAL", 1: "TINYINT", 2: "SMALLINT", 3: "INT", 4: "FLOAT",
         5: "DOUBLE", 6: "NULL", 7: "TIMESTAMP", 8: "BIGINT", 9: "MEDIUMINT",
         10: "DATE", 11: "TIME", 12: "DATETIME", 13: "YEAR", 14: "NEWDATE",
         15: "VARCHAR", 16: "BIT", 17: "TIMESTAMP", 18: "DATETIME", 19: "TIME",
         245: "JSON", 246: "DECIMAL", 247: "ENUM", 248: "SET", 249: "TINYBLOB",
         250: "MEDIUMBLOB", 251: "LONGBLOB", 252: "BLOB", 253: "VARCHAR",
         254: "CHAR", 255: "GEOMETRY"}

NOT_NULL = 256
UNSIGNED = 512
BINARY_TYPE = 1024
NAME_CH = re.compile(rb"[A-Za-z0-9_$]*")


def u(b, o, n):
    if o < 0 or o + n > len(b):
        return -1
    return int.from_bytes(b[o:o + n], "big")


def scan_columns(b, tids, maxcols=1017):
    """tids: iterable of table ids. Returns {tid: {pos: (name, mtype, prtype, len)}}"""
    out = collections.defaultdict(dict)
    votes = collections.defaultdict(collections.Counter)
    for tid in tids:
        pat = tid.to_bytes(8, "big")
        st = 0
        while True:
            q = b.find(pat, st)
            if q < 0:
                break
            st = q + 1
            pos = u(b, q + 8, 4)
            if not 0 <= pos < maxcols:
                continue
            base = q + 25
            m = NAME_CH.match(b, base)
            L = m.end() - base
            if not 1 <= L <= 64:
                continue
            mt = u(b, base + L, 4)
            pr = u(b, base + L + 4, 4)
            ln = u(b, base + L + 8, 4)
            pc = u(b, base + L + 12, 4)
            if mt not in MTYPE or pc != 0:
                continue
            if not 0 < ln < (1 << 24):
                continue
            if (pr & 0xFF) not in MYSQL:
                continue
            name = b[base:base + L].decode("ascii", "ignore")
            votes[tid][(pos, name, mt, pr, ln)] += 1
    for tid, cnt in votes.items():
        for (pos, name, mt, pr, ln), n in cnt.most_common():
            if pos not in out[tid]:
                out[tid][pos] = (name, mt, pr, ln, n)
    return out


def charset_of(prtype):
    return (prtype >> 16) & 0xFFFF


def sql_type(mt, pr, ln):
    """Best-effort MySQL type text from InnoDB dictionary values."""
    code = pr & 0xFF
    unsig = " unsigned" if pr & UNSIGNED else ""
    cs = charset_of(pr)
    mul = 4 if cs in (45, 46, 224, 255, 309) else (3 if cs in (33, 83, 192) else 1)
    name = MYSQL.get(code, "?%d" % code)
    # Temporal types come first: InnoDB keeps them as DATA_INT / DATA_FIXBINARY,
    # so an mtype-first branch would wrongly report them as INT.
    if code in (10, 14):
        return "DATE"
    if code == 13:
        return "YEAR"
    if code in (7, 17):
        return "TIMESTAMP" + frac(ln, 4)
    if code in (12, 18):
        return "DATETIME" + frac(ln, 5)
    if code in (11, 19):
        return "TIME" + frac(ln, 3)
    if code == 16:
        return "BIT(%d)" % (ln * 8)
    if code == 245:
        return "JSON"
    if code in (0, 246):             # DECIMAL / NEWDECIMAL
        return "DECIMAL%s%s" % (decimal_shape(ln), unsig)
    if code == 4 or mt == 9:
        return "FLOAT" + unsig
    if code == 5 or mt == 10:
        return "DOUBLE" + unsig
    if mt == 3:
        return "BINARY(%d)" % ln
    if mt == 4:
        return "VARBINARY(%d)" % ln
    if mt == 6:                      # DATA_INT
        return {1: "TINYINT", 2: "SMALLINT", 3: "MEDIUMINT", 4: "INT",
                8: "BIGINT"}.get(ln, "INT") + unsig
    if code in (1, 2, 3, 8, 9):
        return name + unsig
    if mt == 5 or code in (249, 250, 251, 252):
        blob = {249: "TINY", 250: "MEDIUM", 251: "LONG"}.get(code, "")
        return blob + ("BLOB" if cs == 63 else "TEXT")
    if mt in (1, 12) or code in (15, 253):
        return "VARCHAR(%d)" % max(1, ln // mul)
    if mt in (2, 13) or code == 254:
        return "CHAR(%d)" % max(1, ln // mul)
    if code in (247, 248):
        return name + "(...)"
    return "%s /*mt=%d len=%d*/" % (name, mt, ln)


DIG2BYTES = [0, 1, 1, 2, 2, 3, 3, 4, 4, 4]


def dec_bytes(prec, scale):
    intg, frac_ = prec - scale, scale
    return (intg // 9) * 4 + DIG2BYTES[intg % 9] + (frac_ // 9) * 4 + DIG2BYTES[frac_ % 9]


def decimal_shape(ln):
    """Byte length does not uniquely identify (p,s); prefer money-like shapes."""
    prefer = [(20, 8), (18, 8), (16, 8), (20, 2), (10, 2), (18, 2), (15, 4), (12, 2)]
    for p, s in prefer:
        if dec_bytes(p, s) == ln:
            return "(%d,%d)" % (p, s)
    for p in range(1, 66):
        for s in range(0, min(p, 31) + 1):
            if dec_bytes(p, s) == ln:
                return "(%d,%d)" % (p, s)
    return "(20,8)"


def frac(ln, base):
    return "(%d)" % ((ln - base) * 2) if ln > base else ""


def create_table(name, cols):
    lines = ["CREATE TABLE `%s` (" % name]
    body = []
    for pos in sorted(cols):
        cname, mt, pr, ln, votes = cols[pos]
        nn = " NOT NULL" if pr & NOT_NULL else ""
        body.append("  `%s` %s%s" % (cname, sql_type(mt, pr, ln), nn))
    lines.append(",\n".join(body))
    lines.append(") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;")
    return "\n".join(lines)

# SYS_FIELDS scan: index_id -> ordered index column names (PK order).
# Record layout (REDUNDANT), from record start:
#   +0 INDEX_ID(8)  +8 POS(4)  +12 DB_TRX_ID(6)  +18 DB_ROLL_PTR(7)  +25 COL_NAME(var)
# POS may pack a prefix length: field_no = pos & 0xffff, prefix = pos >> 16.
import re
import struct
import random
import collections

CHR_RE = re.compile(rb"[0-9A-Za-z_$]")


def u(b, o, n):
    v = 0
    for i in range(n):
        v = (v << 8) | b[o + i]
    return v


def name_run(b, o, cap=64):
    e = o
    lim = min(len(b), o + cap)
    while e < lim and CHR_RE.match(b, e):
        e += 1
    return b[o:e]


def scan_fields(b, index_allowed):
    """Return {index_id: {field_no: (name, prefix, votes)}}.

    index_allowed maps index_id -> set of that table's column names (from
    SYS_COLUMNS). The column name is the last field of a SYS_FIELDS record,
    so its end cannot be found by looking at what follows: a neighbouring
    ASCII byte would silently extend the name (e.g. 'user_id' -> 'user_idL').
    We therefore take the longest suffix-free candidate that is a real
    column name of the table, trying longer candidates first.
    """
    out = {}
    for iid, allowed in index_allowed.items():
        votes = collections.defaultdict(collections.Counter)
        pat = re.escape(struct.pack(">Q", iid))
        for m in re.finditer(pat, b):
            q = m.start()
            if q + 26 > len(b):
                continue
            pos = u(b, q + 8, 4)
            fno = pos & 0xFFFF
            prefix = pos >> 16
            if fno > 63 or prefix > 3072:
                continue
            run = name_run(b, q + 25).decode("latin-1")
            if not run or run[:1].isdigit():
                continue
            nm = None
            if allowed:
                for ln in range(len(run), 0, -1):
                    if run[:ln] in allowed:
                        nm = run[:ln]
                        break
                if nm is None:
                    continue
            else:
                nm = run
            votes[fno][(nm, prefix)] += 1
        out[iid] = {f: (c.most_common(1)[0][0][0],
                        c.most_common(1)[0][0][1],
                        c.most_common(1)[0][1])
                    for f, c in votes.items()}
    return out


def pk_columns(fields_for_index):
    """Ordered PK column names from a scan_fields entry."""
    return [fields_for_index[f][0] for f in sorted(fields_for_index)]


# ---------------------------------------------------------------- self-test


# ============================================================ schema assembly
MB_CS = set([33, 45, 46, 83, 192, 193, 194, 195, 196, 197, 198, 199, 200,
             201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212,
             213, 214, 215, 223, 224, 225, 226, 227, 228, 229, 230, 231,
             232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243,
             244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
             275, 309, 326])


def col_meta(name, mt, pr, ln):
    # One column, carrying both def-file text and decode metadata.
    cs = (pr >> 16) & 0xFFFF
    var = mt in (1, 5, 12)
    if mt in (2, 13) and cs in MB_CS:
        var = True
    return dict(name=name, mt=mt, pr=pr, len=ln, code=pr & 0xFF, cs=cs,
                var=var, notnull=bool(pr & NOT_NULL),
                unsigned=bool(pr & UNSIGNED), sql=sql_type(mt, pr, ln))


def clustered(idx_rows):
    # Pick the clustered index out of scan_indexes rows.
    best = None
    for iid, sp, root, nm in idx_rows:
        up = nm.upper()
        rank = 0 if up == 'PRIMARY' else (1 if up == 'GEN_CLUST_INDEX' else 2)
        key = (rank, iid)
        if best is None or key < best[0]:
            best = (key, (iid, sp, root, nm))
    return best[1] if best else None


def build_schema(paths, db=None):
    # SYS_TABLES + SYS_COLUMNS + SYS_FIELDS -> {table: schema}
    tabs, idx, info = dictionary(paths, db)
    tinfo = {}
    for key, votes in tabs.items():
        name, tid, space, ncols = key
        if db and (db + '/') not in name:
            continue
        short = clean(name, db).split('/', 1)[-1]
        cur = tinfo.get(short)
        if cur is None or cur['votes'] < votes:
            tinfo[short] = dict(name=short, full=name, tid=tid, space=space,
                                ncols=ncols & 0x7FFFFFFF, votes=votes)
    out = {}
    if not tinfo:
        return out, info
    b = load(paths[0] if paths else DEF_DICT)
    cols_by_tid = scan_columns(b, [t['tid'] for t in tinfo.values()])
    allowed, clu = {}, {}
    for short, t in tinfo.items():
        c = clustered(idx.get(t['tid'], set()))
        if not c:
            continue
        clu[short] = c
        got = cols_by_tid.get(t['tid'], {})
        allowed[c[0]] = set(v[0] for v in got.values())
    fields = scan_fields(b, allowed) if allowed else {}
    for short, t in tinfo.items():
        raw = cols_by_tid.get(t['tid'], {})
        cols = []
        for p in sorted(raw):
            r = raw[p]
            cols.append(col_meta(r[0], r[1], r[2], r[3]))
        c = clu.get(short)
        pk = pk_columns(fields.get(c[0], {})) if c else []
        known = set(x['name'] for x in cols)
        pk = [p for p in pk if p in known]
        out[short] = dict(table=short, tid=t['tid'], space=t['space'],
                          ncols=t['ncols'], cols=cols, pk=pk,
                          index=(c[0] if c else None),
                          index_name=(c[3] if c else None))
    return out, info


# ================================================================ def files
def emit_def(sch):
    # CREATE TABLE text in the dialect iparse.py accepts.
    body = []
    for c in sch['cols']:
        body.append('  `%s` %s%s' % (c['name'], c['sql'],
                                     ' NOT NULL' if c['notnull'] else ''))
    if sch['pk']:
        keys = ','.join('`%s`' % p for p in sch['pk'])
        body.append('  PRIMARY KEY (%s)' % keys)
    sep = ',' + chr(10)
    return ('CREATE TABLE `%s` (' % sch['table']) + chr(10) + \
        sep.join(body) + chr(10) + ');' + chr(10)


def parse_def(path):
    # Read an existing def file -> ([(name, sqltype, notnull)], pk)
    cols, pk = [], []
    for ln in open(path, encoding='utf-8'):
        ln = ln.strip().rstrip(',')
        if not ln:
            continue
        if 'PRIMARY KEY' in ln.upper():
            pk = re.findall(r'`(\w+)`', ln)
            continue
        m = re.match(r'`(\w+)`\s+(\w+(?:\(\d+(?:,\d+)?\))?)(.*)', ln)
        if not m:
            continue
        cols.append((m.group(1), m.group(2).upper(),
                     'NOT NULL' in m.group(3).upper()))
    return cols, pk


def merge_known(sch, path):
    # Trust an existing hand-checked def for the types it declares.
    try:
        cols, pk = parse_def(path)
    except Exception:
        return 0
    want = {}
    for n, t, nn in cols:
        want[n] = (t, nn)
    hit = 0
    for c in sch['cols']:
        w = want.get(c['name'])
        if not w:
            continue
        c['sql_dict'] = c['sql']
        c['sql'] = w[0]
        c['notnull'] = w[1]
        c['known'] = True
        hit += 1
    if pk:
        sch['pk'] = pk
    return hit


def apply_sql_override(sch):
    # Keep decode metadata in sync when a def type wins over the dictionary.
    for c in sch['cols']:
        m = re.match(r'([A-Z]+)(?:\((\d+)(?:,(\d+))?\))?', c['sql'].upper())
        if not m:
            continue
        base, p1, p2 = m.group(1), m.group(2), m.group(3)
        if base == 'DECIMAL' and p1:
            c['dec'] = (int(p1), int(p2 or 0))
        elif base == 'TIMESTAMP':
            c['force'] = 'ts'
        elif base == 'DATETIME':
            c['force'] = 'dt2'
        elif base == 'DATE':
            c['force'] = 'date'


# ============================================================ value decoding
import datetime
import struct


def dec_int(raw, unsigned):
    if unsigned:
        return int.from_bytes(raw, 'big')
    b = bytearray(raw)
    b[0] ^= 0x80
    return int.from_bytes(bytes(b), 'big', signed=True)


def dec_packed_decimal(raw, prec, scale):
    # MySQL packed decimal: 9 digits per 4 bytes, high bit = sign.
    b = bytearray(raw)
    if not b:
        return '0'
    neg = not (b[0] & 0x80)
    b[0] ^= 0x80
    if neg:
        for i in range(len(b)):
            b[i] ^= 0xFF
    intg = prec - scale
    p = 0
    head = []
    n = intg % 9
    if n:
        w = DIG2BYTES[n]
        head.append(str(int.from_bytes(b[p:p + w], 'big')))
        p += w
    for _ in range(intg // 9):
        head.append('%09d' % int.from_bytes(b[p:p + 4], 'big'))
        p += 4
    ip = ''.join(head).lstrip('0') or '0'
    tail_parts = []
    for _ in range(scale // 9):
        tail_parts.append('%09d' % int.from_bytes(b[p:p + 4], 'big'))
        p += 4
    n = scale % 9
    if n:
        w = DIG2BYTES[n]
        fmt = '%0' + str(n) + 'd'
        tail_parts.append(fmt % int.from_bytes(b[p:p + w], 'big'))
        p += w
    s = ip
    if scale:
        s = s + '.' + ''.join(tail_parts)
    return ('-' + s) if neg else s


def fmt_date3(raw):
    v = int.from_bytes(raw[:3], 'big')
    return '%04d-%02d-%02d' % (v >> 9, (v >> 5) & 0xF, v & 0x1F)


def fmt_ts(raw):
    v = int.from_bytes(raw[:4], 'big')
    if not v:
        return '0000-00-00 00:00:00'
    d = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=v)
    return d.strftime('%Y-%m-%d %H:%M:%S')


def fmt_dt2(raw):
    v = int.from_bytes(raw[:5], 'big') - 0x8000000000
    ymd, hms = v >> 17, v & 0x1FFFF
    ym, d = ymd >> 5, ymd & 0x1F
    return '%04d-%02d-%02d %02d:%02d:%02d' % (ym // 13, ym % 13, d,
                                              hms >> 12, (hms >> 6) & 0x3F,
                                              hms & 0x3F)


def fmt_dt_int(raw):
    b = bytearray(raw[:8])
    b[0] ^= 0x80
    v = abs(int.from_bytes(bytes(b), 'big', signed=True))
    d, t = divmod(v, 1000000)
    return '%04d-%02d-%02d %02d:%02d:%02d' % (d // 10000, (d // 100) % 100,
                                              d % 100, t // 10000,
                                              (t // 100) % 100, t % 100)


def fmt_time2(raw):
    v = int.from_bytes(raw[:3], 'big') - 0x800000
    neg = v < 0
    v = abs(v)
    s = '%02d:%02d:%02d' % ((v >> 12) & 0x3FF, (v >> 6) & 0x3F, v & 0x3F)
    return ('-' + s) if neg else s


def extern_note(raw):
    if len(raw) < 20:
        return '[EXTERN?]'
    r = raw[-20:]
    return '[EXTERN space=%d page=%d off=%d len=%d]' % (
        u(r, 0, 4), u(r, 4, 4), u(r, 8, 4), u(r, 12, 8))


def decimal_pair(ln):
    m = re.match(r'\((\d+),(\d+)\)', decimal_shape(ln))
    return (int(m.group(1)), int(m.group(2))) if m else (20, 8)


def dec_val(c, raw):
    mt, code = c['mt'], c['code']
    force = c.get('force')
    try:
        if c.get('dec') or code in (0, 246):
            p, s = c.get('dec') or decimal_pair(c['len'])
            return dec_packed_decimal(raw, p, s)
        if force == 'date' or code in (10, 14):
            return fmt_date3(raw)
        if force == 'ts' or code in (7, 17):
            return fmt_ts(raw)
        if force == 'dt2' or code == 18:
            return fmt_dt2(raw)
        if code == 12:
            return fmt_dt_int(raw)
        if code == 19:
            return fmt_time2(raw)
        if code == 13:
            return str(1900 + raw[0]) if raw else ''
        if code == 4 or mt == 9:
            return repr(struct.unpack('<f', raw[:4])[0])
        if code == 5 or mt == 10:
            return repr(struct.unpack('<d', raw[:8])[0])
        if mt == 6:
            return dec_int(raw, c['unsigned'])
        if code in (247, 248):
            return int.from_bytes(raw, 'big')
        if mt in (3, 4) and c['cs'] == 63:
            return raw.hex()
        s = raw.decode('utf-8', 'replace')
        return s.rstrip(' ') if code in (2, 254) else s
    except Exception:
        return '[BAD %s]' % raw[:16].hex()


# =========================================================== record decoding
# Unknowns are solved from the bytes, never guessed:
#   * conv: var-length array direction (0 = InnoDB source, 1 = reversed).
#   * pk width: SYS_FIELDS can over-collect key columns.
#   * n_core: fields present in ordinary records. Instant ADD COLUMN leaves
#     older rows physically shorter, with a smaller NULL bitmap.
# The judge is physical tiling: inside a page records are laid end to end,
# so a correct layout makes each record end where the next one starts.
REC_INSTANT = 4


def order_for(sch, pk):
    by = {}
    for c in sch['cols']:
        by[c['name']] = c
    pk = [p for p in pk if p in by]
    order = [dict(by[p], key=True) for p in pk]
    order.append(dict(name='DB_TRX_ID', sys=True, len=6, var=False))
    order.append(dict(name='DB_ROLL_PTR', sys=True, len=7, var=False))
    pks = set(pk)
    for c in sch['cols']:
        if c['name'] not in pks:
            order.append(c)
    return order, pk


def build_layout(sch, pk, conv, n_core):
    order, pk2 = order_for(sch, pk)
    n_core = max(len(pk2) + 2, min(n_core, len(order)))
    cache = {}

    def prep_n(n):
        got = cache.get(n)
        if got is None:
            sub = order[:n]
            nl = [c['name'] for c in sub if not c.get('sys')
                  and not c.get('key') and not c['notnull']]
            got = (sub, nl, (len(nl) + 7) // 8)
            cache[n] = got
        return got

    return dict(order=order, pk=pk2, conv=conv, n_core=n_core, prep=prep_n,
                total=len(order))


def parse_rec(pg, o, lay, keep_deleted=False):
    if o < 12 or o + 2 > PG:
        return dict(err='bounds')
    info = pg[o - 5]
    status = pg[o - 3] & 0x07
    deleted = bool(info & 0x20)
    base = o - 5
    n_fields = lay['n_core']
    if status == REC_INSTANT:
        b = pg[base - 1]
        base -= 1
        if b < 0x80:
            n_add = b
        else:
            n_add = (b & 0x7F) | (pg[base - 1] << 7)
            base -= 1
        n_fields = lay['n_core'] + n_add + 1
    if n_fields > lay['total']:
        return dict(err='nfields')
    sub, nulls, nbm = lay['prep'](n_fields)
    if base - nbm < 10:
        return dict(err='bounds')
    nf = int.from_bytes(pg[base - nbm:base], 'big') if nbm else 0
    isnull = {}
    for i, nm in enumerate(nulls):
        isnull[nm] = bool((nf >> i) & 1)
    pos = base - nbm
    vlen, ext = {}, {}
    seq = sub if lay['conv'] == 0 else list(reversed(sub))
    for c in seq:
        nm = c['name']
        if not c.get('var') or isnull.get(nm):
            continue
        if pos - 2 < 10:
            return dict(err='vlen')
        first, second = pg[pos - 1], pg[pos - 2]
        if c.get('len', 0) < 256 or first < 0x80:
            vlen[nm] = first
            pos -= 1
        elif lay['conv'] == 0:
            vlen[nm] = ((first & 0x3F) << 8) | second
            ext[nm] = bool(first & 0x40)
            pos -= 2
        else:
            vlen[nm] = ((second & 0x3F) << 8) | first
            ext[nm] = bool(second & 0x40)
            pos -= 2
    p = o
    row = {}
    for c in sub:
        nm = c['name']
        if isnull.get(nm):
            row[nm] = None
            continue
        L = vlen.get(nm, 0) if c.get('var') else c['len']
        if L < 0 or p + L > PG:
            return dict(err='len', start=pos)
        raw = pg[p:p + L]
        p += L
        if c.get('sys'):
            continue
        row[nm] = extern_note(raw) if ext.get(nm) else dec_val(c, raw)
    return dict(row=row, start=pos, end=p, status=status, nf=n_fields,
                deleted=deleted)


def page_records(pg, lay, keep_deleted=True):
    out = []
    o, seen = 99, set()
    for _ in range(PG // 5):
        rel = u(pg, o - 2, 2)
        nxt = (o + rel) & 0xFFFF
        if nxt == 112 or nxt < 99 or nxt >= PG or nxt in seen:
            break
        seen.add(nxt)
        o = nxt
        out.append(parse_rec(pg, o, lay, keep_deleted))
    return out


TEMPORAL = (7, 10, 12, 14, 17, 18)


def plausible(c, v):
    if v is None:
        return 0
    if isinstance(v, str):
        if chr(0xFFFD) in v:
            return -2
        for ch in v[:64]:
            if ord(ch) < 32 and ch not in (chr(9), chr(10), chr(13)):
                return -2
    if c['code'] in TEMPORAL and isinstance(v, str) and len(v) >= 4:
        y = v[:4]
        return 1 if (y.isdigit() and 1990 <= int(y) <= 2035) else -2
    if c['code'] in (0, 246) and isinstance(v, str):
        try:
            f = abs(float(v))
        except ValueError:
            return -2
        return 1 if f < 1e12 else -2
    if c['mt'] == 6 and isinstance(v, int):
        return 1 if abs(v) < (1 << 40) else -1
    if isinstance(v, str) and c.get('var'):
        return 1
    return 0


def fit_score(pages, lay):
    # (share of records ending exactly where the next begins, sanity, -errors)
    fit = pairs = errs = rows = pts = 0
    real = [c for c in lay['order'] if not c.get('sys')]
    for pg in pages:
        top = u(pg, 40, 2)
        recs = page_records(pg, lay)
        errs += sum(1 for r in recs if r.get('err'))
        ok = sorted([r for r in recs if r.get('start') is not None
                     and r.get('end')], key=lambda r: r['start'])
        rows += len(ok)
        for i, r in enumerate(ok):
            if r['end'] > top:
                errs += 1
            if i + 1 < len(ok):
                pairs += 1
                if r['end'] == ok[i + 1]['start']:
                    fit += 1
            row = r.get('row') or {}
            for c in real:
                pts += plausible(c, row.get(c['name']))
    ratio = round(fit / pairs, 3) if pairs else 0.0
    avg = round(pts / rows, 2) if rows else 0.0
    return (ratio, avg, -errs)


def solve_layout(pages, sch, deep=True):
    # Search key width, var-length convention and instant field count.
    best = None
    pkv = [sch['pk'][:n] for n in range(len(sch['pk']), 0, -1)] or [[]]
    for pk in pkv:
        order, pk2 = order_for(sch, pk)
        total = len(order)
        nvar = sum(1 for c in order if c.get('var') and not c.get('sys'))
        convs = (0, 1) if nvar > 1 else (0,)
        lo = (len(pk2) + 2) if deep else total
        for n_core in range(total, lo - 1, -1):
            for conv in convs:
                lay = build_layout(sch, pk, conv, n_core)
                sc = fit_score(pages, lay)
                if best is None or sc > best[0]:
                    best = (sc, lay)
            if best and best[0][0] >= 0.995 and best[0][2] == 0:
                break        # this key width is settled; still compare others
    return best


BS = chr(92)
TABC = chr(9)


def tsv_cell(v):
    if v is None:
        return BS + 'N'
    s = v if isinstance(v, str) else str(v)
    s = s.replace(BS, BS + BS)
    s = s.replace(TABC, BS + 't')
    s = s.replace(chr(10), BS + 'n')
    s = s.replace(chr(13), BS + 'r')
    return s


def pad_key(x):
    return x.rjust(24, '0') if x.isdigit() else x


def leaf_pages(files):
    for path in files:
        for _, pg in page_iter(path):
            if u(pg, 24, 2) == 17855 and u(pg, 64, 2) == 0:
                yield pg


def sample_pages(files, n=8):
    out = []
    for pg in leaf_pages(files):
        if u(pg, 54, 2) >= 2:
            out.append(pg)
        if len(out) >= n:
            break
    return out


def dump_table(sch, files, dest, keep_deleted=False, limit=0, lay=None):
    names = [c['name'] for c in sch['cols']]
    if lay is None:
        sample = sample_pages(files)
        if not sample:
            return dict(pages=0, rows=0, errs=collections.Counter(),
                        fit=(0, 0, 0), lay=None)
        sc, lay = solve_layout(sample, sch)
    else:
        sc = (0, 0, 0)
    best = {}
    errs = collections.Counter()
    pages = 0
    pk = lay['pk']
    for pg in leaf_pages(files):
        pages += 1
        lsn = u(pg, 16, 8)
        for r in page_records(pg, lay, keep_deleted):
            if r.get('err'):
                errs[r['err']] += 1
                continue
            if r.get('deleted') and not keep_deleted:
                errs['deleted'] += 1
                continue
            row = r['row']
            key = tuple(str(row.get(k)) for k in (pk or names))
            cur = best.get(key)
            if cur is None or cur[0] < lsn:
                best[key] = (lsn, row)
    kept = 0
    ordered = sorted(best, key=lambda k: [pad_key(x) for x in k])
    fh = open(dest, 'w', encoding='utf-8')
    fh.write(TABC.join(names) + chr(10))
    for key in ordered:
        row = best[key][1]
        fh.write(TABC.join(tsv_cell(row.get(n)) for n in names) + chr(10))
        kept += 1
        if limit and kept >= limit:
            break
    fh.close()
    return dict(pages=pages, rows=kept, errs=errs, fit=sc, lay=lay)


# ==================================================================== modes
DEF_DEFS6 = '/mnt/recovery/defs6'
DEF_TSV = '/mnt/recovery/tsv'
IX_RE = re.compile(r'\.ix(\d+)\.page$')


def prep(sch, nm, known):
    kp = os.path.join(known, nm + '.sql') if known else None
    hit = 0
    if kp and os.path.exists(kp):
        hit = merge_known(sch, kp)
    apply_sql_override(sch)
    return hit


def group_by_index(files):
    g = {}
    for f in files:
        m = IX_RE.search(f)
        g.setdefault(int(m.group(1)) if m else 0, []).append(f)
    return g


def choose_files(src, nm, sch):
    # Prefer the clustered index from the dictionary; otherwise score the
    # available indexes and use the one that decodes as a table.
    g = group_by_index(sorted(glob.glob(os.path.join(src, '%s.sp*.page' % nm))))
    if not g:
        return [], None, 'nofiles'
    cl = sch.get('index')
    if cl in g:
        return g[cl], cl, 'dict'
    if len(g) == 1:
        ix = list(g)[0]
        return g[ix], ix, 'only'
    best = None
    for ix, fl in sorted(g.items()):
        sample = sample_pages(fl, 4)
        if not sample:
            continue
        sc = solve_layout(sample, sch)[0]
        if best is None or sc > best[0]:
            best = (sc, ix, fl)
    if best is None:
        return [], None, 'empty'
    return best[2], best[1], 'scored'


def do_cols(pos, opt):
    paths = pos or [DEF_DICT]
    db = None if opt.get('all') else opt.get('db', 'foxcoin_app')
    only = opt.get('table')
    sch, info = build_schema(paths, db)
    for line in info:
        print(line)
    print('# table cols/ncols pk index')
    for nm in sorted(sch):
        if only and only != nm:
            continue
        s = sch[nm]
        flag = 'ok' if len(s['cols']) == s['ncols'] else 'PARTIAL'
        print('%-28s %3d/%-3d %-7s pk=%-16s ix=%s'
              % (nm, len(s['cols']), s['ncols'], flag,
                 ','.join(s['pk']) or '-', s['index']))
        if only:
            for c in s['cols']:
                print('    %-26s %-20s %s'
                      % (c['name'], c['sql'],
                         'NOT NULL' if c['notnull'] else 'NULL'))
    done = sum(1 for s in sch.values() if len(s['cols']) == s['ncols'])
    print('# tables %d complete %d' % (len(sch), done))


def do_defs(pos, opt):
    paths = pos or [DEF_DICT]
    db = None if opt.get('all') else opt.get('db', 'foxcoin_app')
    outdir = opt.get('out', DEF_DEFS6)
    known = opt.get('merge', DEF_DEFS)
    os.makedirs(outdir, exist_ok=True)
    sch, info = build_schema(paths, db)
    for line in info:
        print(line)
    n = 0
    for nm in sorted(sch):
        s = sch[nm]
        if not s['cols']:
            print('%-28s NO COLUMNS' % nm)
            continue
        hit = prep(s, nm, known)
        fh = open(os.path.join(outdir, nm + '.sql'), 'w', encoding='utf-8')
        fh.write(emit_def(s))
        fh.close()
        n += 1
        if opt.get('v'):
            print('%-28s %3d %-18s %s'
                  % (nm, len(s['cols']), ','.join(s['pk']) or '-',
                     ('merged %d' % hit) if hit else 'dict'))
    print('# wrote %d defs to %s' % (n, outdir))


def do_dump(pos, opt):
    paths = [opt.get('dict', DEF_DICT)]
    db = None if opt.get('all') else opt.get('db', 'foxcoin_app')
    src = opt.get('in', DEF_OUT)
    outdir = opt.get('out', DEF_TSV)
    only = opt.get('table')
    limit = int(opt.get('limit', 0))
    keep_del = bool(opt.get('deleted'))
    known = opt.get('merge', DEF_DEFS)
    os.makedirs(outdir, exist_ok=True)
    sch, info = build_schema(paths, db)
    for line in info:
        print(line)
    print('# table pages rows fit key conv core/all errors')
    tot, done, empty, weak = 0, 0, [], []
    for nm in sorted(sch):
        if only and only != nm:
            continue
        s = sch[nm]
        if not s['cols']:
            continue
        files, ix, why = choose_files(src, nm, s)
        if not files:
            empty.append(nm)
            continue
        prep(s, nm, known)
        r = dump_table(s, files, os.path.join(outdir, nm + '.tsv'),
                       keep_del, limit)
        lay = r['lay']
        if lay is None:
            empty.append(nm)
            continue
        bad = ','.join('%s=%d' % kv for kv in r['errs'].most_common(2))
        print('%-24s %5d %7d %5.2f %-12s c%d %2d/%-2d %s'
              % (nm, r['pages'], r['rows'], r['fit'][0],
                 ','.join(lay['pk'])[:12] or '-', lay['conv'],
                 lay['n_core'], lay['total'], bad or '-'))
        if r['fit'][0] < 0.9:
            weak.append(nm)
        tot += r['rows']
        done += 1
    if empty:
        print('# no pages: ' + ' '.join(empty[:8]) +
              (' +%d' % (len(empty) - 8) if len(empty) > 8 else ''))
    if weak:
        print('# low fit: ' + ' '.join(weak[:8]) +
              (' +%d' % (len(weak) - 8) if len(weak) > 8 else ''))
    print('# tables %d rows %d -> %s' % (done, tot, outdir))


def do_diag(pos, opt):
    # Byte-level view of one page: page header, record headers, solved layout.
    nm = opt.get('table', 'users')
    src = opt.get('in', DEF_OUT)
    paths = [opt.get('dict', DEF_DICT)]
    db = None if opt.get('all') else opt.get('db', 'foxcoin_app')
    nrec = int(opt.get('recs', 2))
    sch, _ = build_schema(paths, db)
    s = sch.get(nm)
    if not s:
        print('no dictionary entry for %s' % nm)
        return
    prep(s, nm, opt.get('merge', DEF_DEFS))
    files, ix, why = choose_files(src, nm, s)
    if not files:
        print('no pages for %s in %s' % (nm, src))
        return
    sample = sample_pages(files)
    if not sample:
        print('no leaf pages with records')
        return
    pg = sample[0]
    print('%s ix=%s(%s) files=%d cols=%d' % (nm, ix, why, len(files),
                                             len(s['cols'])))
    print('page=%d recs=%d heap=%d top=%d free=%d instant=%d'
          % (u(pg, 4, 4), u(pg, 54, 2), u(pg, 42, 2) & 0x7FFF,
             u(pg, 40, 2), u(pg, 44, 2), u(pg, 50, 2) >> 3))
    sc, lay = solve_layout(sample, s)
    print('solved pk=%s conv=%d core=%d/%d fit=%s sanity=%s errs=%d'
          % (','.join(lay['pk']) or '-', lay['conv'], lay['n_core'],
             lay['total'], sc[0], sc[1], -sc[2]))
    o, n = 99, 0
    while n < nrec:
        o = (o + u(pg, o - 2, 2)) & 0xFFFF
        if o == 112 or o < 99 or o >= PG:
            break
        n += 1
        r = parse_rec(pg, o, lay, True)
        print('rec@%d st=%d info=%02x pre=%s'
              % (o, pg[o - 3] & 7, pg[o - 5], pg[max(0, o - 12):o].hex()))
        if r.get('err'):
            print('   err=%s' % r['err'])
            continue
        print('   fields=%d bytes=%d..%d' % (r['nf'], r['start'], r['end']))
        for c in s['cols'][:7]:
            print('   %-20s %s' % (c['name'], str(r['row'].get(c['name']))[:52]))


def do_xcheck(pos, opt):
    nm = opt.get('table', 'shop_items')
    src = opt.get('in', DEF_OUT)
    defs = opt.get('defs', DEF_DEFS)
    iparse = opt.get('iparse', IPARSE)
    paths = [opt.get('dict', DEF_DICT)]
    db = None if opt.get('all') else opt.get('db', 'foxcoin_app')
    sch, _ = build_schema(paths, db)
    s = sch.get(nm)
    if not s:
        print('no dictionary entry for %s' % nm)
        return
    files, ix, why = choose_files(src, nm, s)
    if not files:
        print('no pages for %s in %s' % (nm, src))
        return
    prep(s, nm, defs)
    mine = os.path.join(src, nm + '.mine.tsv')
    r = dump_table(s, files[:1], mine, False, 0)
    a = [l.rstrip(chr(10)) for l in open(mine, encoding='utf-8')][1:]
    lay = r['lay']
    print('%s ix=%s(%s) pages=%d rows=%d fit=%s key=%s conv=%d core=%d/%d'
          % (nm, ix, why, r['pages'], r['rows'], r['fit'][0],
             ','.join(lay['pk']) or '-', lay['conv'], lay['n_core'],
             lay['total']))
    for x in a[:4]:
        print('  ours %s' % x[:130])
    dpath = os.path.join(defs, nm + '.sql')
    if not os.path.exists(dpath) or not os.path.exists(iparse):
        print('  (no iparse def, nothing to compare)')
        return
    theirs = os.path.join(src, nm + '.iparse.tsv')
    fh = open(theirs, 'wb')
    subprocess.run([sys.executable, iparse, dpath, files[0]], stdout=fh,
                   stderr=subprocess.DEVNULL)
    fh.close()
    b2 = [l.rstrip(chr(10)) for l in
          open(theirs, encoding='utf-8', errors='replace')]
    print('  iparse rows %d identical %d' % (len(b2), len(set(a) & set(b2))))


MODES = {"cols": do_cols, "defs": do_defs, "dump": do_dump,
         "xcheck": do_xcheck, "diag": do_diag, "probe": do_probe, "map": do_map, "inv": do_inv,
         "plan": do_plan, "auto": do_auto, "pull": do_pull}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in MODES:
        print("usage: rec6.py probe|map|inv|plan|auto|pull|cols|defs|dump|diag|xcheck ...")
        return 1
    pos, opt = split_args(sys.argv[2:])
    MODES[sys.argv[1]](pos, opt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
