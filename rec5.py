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


MODES = {"probe": do_probe, "map": do_map, "inv": do_inv,
         "plan": do_plan, "auto": do_auto, "pull": do_pull}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in MODES:
        print("usage: rec5.py probe|map|inv|plan|auto|pull ...")
        return 1
    pos, opt = split_args(sys.argv[2:])
    MODES[sys.argv[1]](pos, opt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
