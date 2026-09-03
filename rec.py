#!/usr/bin/env python3
# InnoDB recovery helper -- three modes, no guessing.
#
#   python3 rec.py map  [ibdata1] [name-filter]
#       Reads SYS_TABLES + SYS_INDEXES straight out of ibdata1 raw bytes,
#       including records purge removed from the record chain but which still
#       sit in page garbage areas -- that is where DROPped tables live.
#       Prints: table  table_id  space  index_id  root_page
#
#   python3 rec.py inv  [pages-dir]
#       Inventories carved pages grouped by (space_id, index_id).
#
#   python3 rec.py pull <space_id> <index_id> <out.page> [pages-dir]
#       Extracts pages of exactly one table, newest version of each page
#       number (highest FIL_PAGE_LSN), ordered by page number.
#
# Layouts (MariaDB 10.x keeps the classic InnoDB dictionary, REDUNDANT rows):
#   SYS_TABLES : NAME(var)|TRX(6)|ROLL(7)|ID(8)|N_COLS(4)|TYPE(4)|MIX_ID(8)|MIX_LEN(4)|CLUSTER_NAME(0)|SPACE(4)
#   SYS_INDEXES: TABLE_ID(8)|ID(8)|TRX(6)|ROLL(7)|NAME(var)|N_FIELDS(4)|TYPE(4)|SPACE(4)|PAGE_NO(4)
# Page header: 4 page_no | 16 LSN | 24 type (17855=INDEX) | 34 space_id | 54 n_recs | 64 level | 66 index_id
import re, sys, glob, os, collections

PG = 16384
DEFAULT_PAGES = "/mnt/recovery/pages4/FIL_PAGE_INDEX"
DEFAULT_IBD = "/mnt/main/var/lib/mysql/ibdata1"


def do_map(argv):
    path = argv[0] if argv else DEFAULT_IBD
    flt = argv[1] if len(argv) > 1 else ""
    b = open(path, "rb").read()

    tabs = collections.Counter()
    for m in re.finditer(rb"[a-z0-9_]{2,30}/[a-zA-Z0-9_]{2,50}", b):
        e = m.end()
        if e + 45 > len(b):
            continue
        name = m.group().decode("ascii", "ignore")
        if "/fk_" in name:
            continue
        tid = int.from_bytes(b[e + 13:e + 21], "big")
        ncols = int.from_bytes(b[e + 21:e + 25], "big")
        space = int.from_bytes(b[e + 41:e + 45], "big")
        if 0 < tid < 10 ** 6 and 0 < ncols < 300 and 0 < space < 10 ** 6:
            tabs[(name, tid, space)] += 1

    idx = collections.defaultdict(set)
    for m in re.finditer(rb"PRIMARY|GEN_CLUST_INDEX", b):
        p, e = m.start(), m.end()
        if p < 29 or e + 16 > len(b):
            continue
        tid = int.from_bytes(b[p - 29:p - 21], "big")
        iid = int.from_bytes(b[p - 21:p - 13], "big")
        space = int.from_bytes(b[e + 8:e + 12], "big")
        root = int.from_bytes(b[e + 12:e + 16], "big")
        if 0 < tid < 10 ** 6 and 0 < iid < 10 ** 6 and 0 < space < 10 ** 6 and 0 < root < 10 ** 7:
            idx[tid].add((iid, space, root))

    print("# SYS_TABLES candidates: %d | SYS_INDEXES table_ids: %d" % (len(tabs), len(idx)))
    print("# table\ttable_id\tspace\tindex_id\troot_page")
    ok = 0
    miss = 0
    for (name, tid, space) in sorted(tabs):
        if flt and flt not in name:
            continue
        rows = sorted(r for r in idx.get(tid, ()) if r[1] == space)
        if rows:
            ok += 1
            for iid, sp, root in rows:
                print("%s\t%d\t%d\t%d\t%d" % (name, tid, sp, iid, root))
        else:
            miss += 1
            print("%s\t%d\t%d\t-\t-" % (name, tid, space))
    print("# consistent: %d | no index match: %d" % (ok, miss))


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
        if int.from_bytes(p[24:26], "big") != 17855:
            continue
        key = (int.from_bytes(p[34:38], "big"), int.from_bytes(p[66:74], "big"))
        total[key] += 1
        if int.from_bytes(p[64:66], "big") == 0:
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
        if int.from_bytes(p[24:26], "big") != 17855:
            continue
        if int.from_bytes(p[34:38], "big") != space:
            continue
        if int.from_bytes(p[66:74], "big") != index:
            continue
        no = int.from_bytes(p[4:8], "big")
        lsn = int.from_bytes(p[16:24], "big")
        if no in best:
            dupes += 1
            if best[no][0] >= lsn:
                continue
        best[no] = (lsn, p)
    with open(dest, "wb") as out:
        for no in sorted(best):
            out.write(best[no][1])
    leaves = sum(1 for _, p in best.values() if int.from_bytes(p[64:66], "big") == 0)
    recs = sum(int.from_bytes(p[54:56], "big") for _, p in best.values()
               if int.from_bytes(p[64:66], "big") == 0)
    print("pages=%d leaf=%d n_recs_sum=%d older_versions_skipped=%d -> %s"
          % (len(best), leaves, recs, dupes, dest))


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("map", "inv", "pull"):
        print(__doc__ or "usage: rec.py map|inv|pull ...")
        print("usage: rec.py map [ibdata1] [filter] | rec.py inv [pages-dir] | rec.py pull <space> <index> <out.page> [pages-dir]")
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
