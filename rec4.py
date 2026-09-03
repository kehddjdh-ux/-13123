#!/usr/bin/env python3
# InnoDB recovery helper v4
# SYS_TABLES offsets CONFIRMED byte-for-byte against two identical copies of a
# real record (mysql/innodb_table_stats at 11063 and 27447 of the carved
# SYS_TABLES page) and cross-checked with c_parser values (14, 6, 33, 0, 80, 1):
#
#   NAME(var) | 8 bytes | ID(8B BE) @+8 | 5 bytes | N_COLS(4B) @+21 |
#   TYPE(4B) @+25 | MIX_ID(8B) @+29 | MIX_LEN(4B) @+37 | SPACE(4B) @+41 |
#   fixed tail = 45 bytes, then next record header
#
# SYS_INDEXES: TABLE_ID(8B)+ID(8B) found in the 40 bytes before NAME,
# validated against table ids from SYS_TABLES; after NAME the canonical
# positions SPACE(4B)@+8 PAGE_NO(4B)@+12 are tried first, with a validated
# fallback scan.
#
# Modes:
#   python3 rec4.py map  [ibdata1] [name-filter]
#   python3 rec4.py inv  [pages-dir]
#   python3 rec4.py pull <space_id> <index_id> <out.page> [pages-dir]
import re
import sys
import glob
import os
import collections

PG = 16384
DEFAULT_PAGES = "/mnt/recovery/pages4/FIL_PAGE_INDEX"
DEFAULT_IBD = "/mnt/main/var/lib/mysql/ibdata1"


def u(b, o, n):
    return int.from_bytes(b[o:o + n], "big")


def scan_tables(b):
    out = collections.Counter()
    for m in re.finditer(rb"[a-z0-9_]{2,30}/[a-zA-Z0-9_]{2,50}", b):
        e = m.end()
        if e + 45 > len(b):
            continue
        name = m.group().decode("ascii", "ignore")
        if "/fk_" in name:
            continue
        tid = u(b, e + 8, 8)
        ncols = u(b, e + 21, 4)
        ttype = u(b, e + 25, 4)
        space = u(b, e + 41, 4)
        if not (0 < tid < 10 ** 6):
            continue
        if not (0 < ncols < 300):
            continue
        if not (0 < ttype < 10 ** 6):
            continue
        if not (0 < space < 10 ** 6):
            continue
        out[(name, tid, space, ncols)] += 1
    return out


def scan_indexes(b, space_of):
    known = set(space_of)
    found = collections.defaultdict(set)
    for m in re.finditer(rb"PRIMARY|GEN_CLUST_INDEX", b):
        p, e = m.start(), m.end()
        if p < 40 or e + 16 > len(b):
            continue
        pre = b[p - 40:p]
        post = b[e:e + 40]
        for off in range(0, 25):
            tid = u(pre, off, 8)
            if tid not in known:
                continue
            iid = u(pre, off + 8, 8)
            if not (0 < iid < 10 ** 9):
                continue
            want = space_of[tid]
            root = None
            if u(post, 8, 4) == want and 0 < u(post, 12, 4) < 10 ** 7:
                root = u(post, 12, 4)
            else:
                for j in range(0, 33):
                    if u(post, j, 4) == want and 0 < u(post, j + 4, 4) < 10 ** 7:
                        root = u(post, j + 4, 4)
                        break
            if root:
                found[tid].add((iid, want, root))
            break
    return found


def do_map(argv):
    path = argv[0] if argv else DEFAULT_IBD
    flt = argv[1] if len(argv) > 1 else ""
    b = open(path, "rb").read()
    tabs = scan_tables(b)
    space_of = {}
    for (name, tid, space, ncols) in tabs:
        space_of[tid] = space
    idx = scan_indexes(b, space_of)
    print("# file: %s (%d bytes)" % (path, len(b)))
    print("# SYS_TABLES records: %d | tables with index info: %d"
          % (len(tabs), len(idx)))
    print("# table\ttable_id\tspace\tncols\tindex_id\troot_page")
    ok = 0
    miss = 0
    for (name, tid, space, ncols) in sorted(tabs):
        if flt and flt not in name:
            continue
        rows = sorted(r for r in idx.get(tid, ()) if r[1] == space)
        if rows:
            ok += 1
            for iid, sp, root in rows:
                print("%s\t%d\t%d\t%d\t%d\t%d"
                      % (name, tid, sp, ncols, iid, root))
        else:
            miss += 1
            print("%s\t%d\t%d\t%d\t-\t-" % (name, tid, space, ncols))
    print("# with index: %d | without: %d" % (ok, miss))


def iter_pages(pages_dir):
    for f in sorted(glob.glob(os.path.join(pages_dir, "*.page"))):
        b = open(f, "rb").read()
        for o in range(0, len(b) - PG + 1, PG):
            yield b[o:o + PG]


def do_inv(argv):
    pages_dir = argv[0] if argv else DEFAULT_PAGES
    total = collections.Counter()
    leaf = collections.Counter()
    for p in iter_pages(pages_dir):
        if u(p, 24, 2) != 17855:
            continue
        key = (u(p, 34, 4), u(p, 66, 8))
        total[key] += 1
        if u(p, 64, 2) == 0:
            leaf[key] += 1
    print("# groups: %d" % len(total))
    print("# space\tindex_id\tpages\tleaf")
    for (sp, ix), n in total.most_common(80):
        print("%d\t%d\t%d\t%d" % (sp, ix, n, leaf[(sp, ix)]))


def do_pull(argv):
    space = int(argv[0])
    index = int(argv[1])
    dest = argv[2]
    pages_dir = argv[3] if len(argv) > 3 else DEFAULT_PAGES
    best = {}
    dupes = 0
    for p in iter_pages(pages_dir):
        if u(p, 24, 2) != 17855:
            continue
        if u(p, 34, 4) != space:
            continue
        if u(p, 66, 8) != index:
            continue
        no = u(p, 4, 4)
        lsn = u(p, 16, 8)
        if no in best:
            dupes += 1
            if best[no][0] >= lsn:
                continue
        best[no] = (lsn, p)
    with open(dest, "wb") as out:
        for no in sorted(best):
            out.write(best[no][1])
    leaves = sum(1 for _, p in best.values() if u(p, 64, 2) == 0)
    recs = sum(u(p, 54, 2) for _, p in best.values() if u(p, 64, 2) == 0)
    print("pages=%d leaf=%d n_recs_sum=%d older_skipped=%d -> %s"
          % (len(best), leaves, recs, dupes, dest))


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("map", "inv", "pull"):
        print("usage:")
        print("  rec4.py map [ibdata1] [filter]")
        print("  rec4.py inv [pages-dir]")
        print("  rec4.py pull <space> <index> <out.page> [pages-dir]")
        return 1
    mode = sys.argv[1]
    rest = sys.argv[2:]
    if mode == "map":
        do_map(rest)
    elif mode == "inv":
        do_inv(rest)
    else:
        do_pull(rest)
    return 0


sys.exit(main())
