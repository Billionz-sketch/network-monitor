"""Tiny dependency-free QR code generator (byte mode, ECC level M, versions 1-10) -> SVG."""

_ECC_PER_BLOCK = [None, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26]
_NUM_BLOCKS = [None, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5]


def _raw_modules(v):
    r = (16 * v + 128) * v + 64
    if v >= 2:
        n = v // 7 + 2
        r -= (25 * n - 10) * n - 55
        if v >= 7:
            r -= 36
    return r


def _mul(x, y):
    z = 0
    for i in range(7, -1, -1):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _rs_divisor(deg):
    res = [0] * (deg - 1) + [1]
    root = 1
    for _ in range(deg):
        for j in range(deg):
            res[j] = _mul(res[j], root)
            if j + 1 < deg:
                res[j] ^= res[j + 1]
        root = _mul(root, 2)
    return res


def _rs_remainder(data, div):
    res = [0] * len(div)
    for b in data:
        f = b ^ res.pop(0)
        res.append(0)
        for i, c in enumerate(div):
            res[i] ^= _mul(c, f)
    return res


def _encode_data(payload, v):
    cap = _raw_modules(v) // 8 - _ECC_PER_BLOCK[v] * _NUM_BLOCKS[v]
    bits = [0, 1, 0, 0]
    cc = 8 if v < 10 else 16
    bits += [(len(payload) >> i) & 1 for i in range(cc - 1, -1, -1)]
    for b in payload:
        bits += [(b >> i) & 1 for i in range(7, -1, -1)]
    bits += [0] * min(4, cap * 8 - len(bits))
    bits += [0] * (-len(bits) % 8)
    data = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(data) < cap:
        data.append(pad)
        pad ^= 0xEC ^ 0x11
    return data


def _interleave(data, v):
    nb, el = _NUM_BLOCKS[v], _ECC_PER_BLOCK[v]
    raw = _raw_modules(v) // 8
    nshort = nb - raw % nb
    slen = raw // nb
    div = _rs_divisor(el)
    blocks, k = [], 0
    for i in range(nb):
        d = data[k:k + slen - el + (0 if i < nshort else 1)]
        k += len(d)
        ecc = _rs_remainder(d, div)
        if i < nshort:
            d = d + [0]
        blocks.append(d + ecc)
    out = []
    for i in range(len(blocks[0])):
        for j, b in enumerate(blocks):
            if i != slen - el or j >= nshort:
                out.append(b[i])
    return out


def _align_positions(v):
    if v == 1:
        return []
    n = v // 7 + 2
    step = (v * 4 + n * 2 + 1) // (n * 2 - 2) * 2
    size = v * 4 + 17
    res = list(range(size - 7, 6, -step)) + [6]
    return res[::-1]


def _penalty(m, size):
    p = 0
    for grid in (m, [list(c) for c in zip(*m)]):
        for row in grid:
            run, prev = 1, row[0]
            for x in range(1, size):
                if row[x] == prev:
                    run += 1
                else:
                    if run >= 5: p += run - 2
                    run, prev = 1, row[x]
            if run >= 5: p += run - 2
            s = "".join("1" if c else "0" for c in row)
            p += 40 * (s.count("10111010000") + s.count("00001011101"))
    for y in range(size - 1):
        for x in range(size - 1):
            if m[y][x] == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                p += 3
    dark = sum(map(sum, m))
    k = abs(dark * 20 - size * size * 10) // (size * size)
    return p + 10 * k


def make_matrix(text):
    payload = text.encode("utf-8")
    v = next((x for x in range(1, 11)
              if len(payload) <= _raw_modules(x) // 8 - _ECC_PER_BLOCK[x] * _NUM_BLOCKS[x] - (2 if x < 10 else 3)), None)
    if v is None:
        raise ValueError("text too long for QR")
    size = v * 4 + 17
    mod = [[False] * size for _ in range(size)]
    fn = [[False] * size for _ in range(size)]

    def setf(x, y, dark):
        if 0 <= x < size and 0 <= y < size:
            mod[y][x] = dark
            fn[y][x] = True

    for i in range(size):
        setf(6, i, i % 2 == 0); setf(i, 6, i % 2 == 0)
    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                d = max(abs(dx), abs(dy))
                setf(cx + dx, cy + dy, d not in (2, 4))
    pos = _align_positions(v)
    for i, a in enumerate(pos):
        for j, b in enumerate(pos):
            if (i == 0 and j == 0) or (i == 0 and j == len(pos) - 1) or (i == len(pos) - 1 and j == 0):
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    setf(a + dx, b + dy, max(abs(dx), abs(dy)) != 1)

    def fmt(mask):
        data = (0 << 3) | mask          # ECC level M = 0b00
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = ((data << 10) | rem) ^ 0x5412
        g = lambda i: (bits >> i) & 1 == 1
        for i in range(6): setf(8, i, g(i))
        setf(8, 7, g(6)); setf(8, 8, g(7)); setf(7, 8, g(8))
        for i in range(9, 15): setf(14 - i, 8, g(i))
        for i in range(8): setf(size - 1 - i, 8, g(i))
        for i in range(8, 15): setf(8, size - 15 + i, g(i))
        setf(8, size - 8, True)

    fmt(0)  # reserve
    if v >= 7:
        rem = v
        for _ in range(12):
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
        bits = (v << 12) | rem
        for i in range(18):
            b = (bits >> i) & 1 == 1
            a, c = size - 11 + i % 3, i // 3
            setf(a, c, b); setf(c, a, b)

    cw = _interleave(_encode_data(payload, v), v)
    i = 0
    for right in range(size - 1, 0, -2):
        if right == 6:
            right = 5
        for vert in range(size):
            for j in range(2):
                x = right - j
                upward = ((right + 1) & 2) == 0
                y = size - 1 - vert if upward else vert
                if not fn[y][x] and i < len(cw) * 8:
                    mod[y][x] = ((cw[i >> 3] >> (7 - (i & 7))) & 1) == 1
                    i += 1

    masks = [lambda x, y: (x + y) % 2 == 0, lambda x, y: y % 2 == 0, lambda x, y: x % 3 == 0,
             lambda x, y: (x + y) % 3 == 0, lambda x, y: (x // 3 + y // 2) % 2 == 0,
             lambda x, y: x * y % 2 + x * y % 3 == 0, lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
             lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0]
    best, best_p = None, None
    for mk in range(8):
        m = [[mod[y][x] ^ (not fn[y][x] and masks[mk](x, y)) for x in range(size)] for y in range(size)]
        saved = [r[:] for r in mod]
        mod[:] = [r[:] for r in m]
        fmt(mk)
        cand = [r[:] for r in mod]
        mod[:] = saved
        p = _penalty(cand, size)
        if best_p is None or p < best_p:
            best, best_p = cand, p
    return best


def make_svg(text, scale=8, border=4):
    m = make_matrix(text)
    n = len(m)
    tot = (n + 2 * border) * scale
    parts = []
    for y, row in enumerate(m):
        for x, d in enumerate(row):
            if d:
                parts.append(f"M{(x + border) * scale},{(y + border) * scale}h{scale}v{scale}h-{scale}z")
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {tot} {tot}" width="{tot}" height="{tot}" shape-rendering="crispEdges">'
            f'<rect width="100%" height="100%" fill="#fff"/><path d="{"".join(parts)}" fill="#000"/></svg>')
