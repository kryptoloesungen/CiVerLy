"""
KATAN implementation for CiVerLy.

Reference implementation and attribution: https://gist.github.com/raullenchai/2712516

This Python/Sage implementation was validated against the C reference
included in documentation/reference_implementation_katan.c. Consult the
original sources for licensing and full attribution.
"""

from sage.crypto.sbox import SBox

from civerly.component import SBox_CVL
from civerly.sboxcipher import SBoxCipher

PARAMS = {
    32: {
        "l1": 13,
        "l2": 19,
        "fa": (12, 7, 8, 5, 3),
        "fb": (18, 7, 12, 10, 8, 3),
        "steps": 1,
    },
    48: {
        "l1": 19,
        "l2": 29,
        "fa": (18, 12, 15, 7, 6),
        "fb": (28, 19, 21, 13, 15, 6),
        "steps": 2,
    },
    64: {
        "l1": 25,
        "l2": 39,
        "fa": (24, 15, 20, 11, 9),
        "fb": (38, 25, 33, 21, 14, 9),
        "steps": 3,
    },
}


def _key_bits(key, rounds):
    bits = [(int(key) >> i) & 1 for i in range(80)]
    for i in range(80, 2 * rounds):
        bits.append(bits[i - 80] ^ bits[i - 61] ^ bits[i - 50] ^ bits[i - 13])
    return bits


def _ir_bits(rounds):
    r"""
    Return the first ``rounds`` irregular-update bits used by KATAN.

    The sequence is taken directly from Table 3 of the KATAN paper (and the
    reference C implementation).  Using the literal table avoids any risk of
    an LFSR endinaness or tap-interpretation mismatch.
    """
    # fmt: off
    table = [
        1, 1, 1, 1, 1, 1, 1, 0, 0, 0,
        1, 1, 0, 1, 0, 1, 0, 1, 0, 1,
        1, 1, 1, 0, 1, 1, 0, 0, 1, 1,
        0, 0, 1, 0, 1, 0, 0, 1, 0, 0,
        0, 1, 0, 0, 0, 1, 1, 0, 0, 0,
        1, 1, 1, 1, 0, 0, 0, 0, 1, 0,
        0, 0, 0, 1, 0, 1, 0, 0, 0, 0,
        0, 1, 1, 1, 1, 1, 0, 0, 1, 1,
        1, 1, 1, 1, 0, 1, 0, 1, 0, 0,
        0, 1, 0, 1, 0, 1, 0, 0, 1, 1,
        0, 0, 0, 0, 1, 1, 0, 0, 1, 1,
        1, 0, 1, 1, 1, 1, 1, 0, 1, 1,
        1, 0, 1, 0, 0, 1, 0, 1, 0, 1,
        1, 0, 1, 0, 0, 1, 1, 1, 0, 0,
        1, 1, 0, 1, 1, 0, 0, 0, 1, 0,
        1, 1, 1, 0, 1, 1, 0, 1, 1, 1,
        1, 0, 0, 1, 0, 1, 1, 0, 1, 1,
        0, 1, 0, 1, 1, 1, 0, 0, 1, 0,
        0, 1, 0, 0, 1, 1, 0, 1, 0, 0,
        0, 1, 1, 1, 0, 0, 0, 1, 0, 0,
        1, 1, 1, 1, 0, 1, 0, 0, 0, 0,
        1, 1, 1, 0, 1, 0, 1, 1, 0, 0,
        0, 0, 0, 1, 0, 1, 1, 0, 0, 1,
        0, 0, 0, 0, 0, 0, 1, 1, 0, 1,
        1, 1, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 1, 0,
    ]
    # fmt: on
    if rounds > len(table):
        raise ValueError("Invalid number of rounds for KATAN")
    return table[:rounds]


def _fa_sbox(ir_bit, key_bit):
    table = []
    for value in range(1 << 5):
        bits = [(value >> (4 - i)) & 1 for i in range(5)]
        output = bits[0] ^ bits[1] ^ (bits[2] & bits[3])
        if ir_bit:
            output ^= bits[4]
        output ^= key_bit
        table.append(output)
    return SBox(table)


def _fb_sbox(key_bit):
    table = []
    for value in range(1 << 6):
        bits = [(value >> (5 - i)) & 1 for i in range(6)]
        output = bits[0] ^ bits[1] ^ (bits[2] & bits[3]) ^ (bits[4] & bits[5])
        output ^= key_bit
        table.append(output)
    return SBox(table)


def reference_katan_encrypt(variant, plaintext_int, key_int, rounds):
    r"""Reference Python implementation mirroring the C reference.

    Returns integer ciphertext. Used for doctests.
    """
    params = PARAMS[variant]
    l1 = params["l1"]
    l2 = params["l2"]
    fa_pos = params["fa"]
    fb_pos = params["fb"]

    # initialize L1 and L2 as lists of bits, index 0 = least significant
    L2 = [(plaintext_int >> i) & 1 for i in range(l2)]
    L1 = [((plaintext_int >> (l2 + i)) & 1) for i in range(l1)]

    k = _key_bits(key_int, rounds)
    ir = _ir_bits(rounds)

    for r in range(rounds):
        # all steps of a round use the same key and IR bits
        for _ in range(params["steps"]):
            fa = (
                L1[fa_pos[0]]
                ^ L1[fa_pos[1]]
                ^ (L1[fa_pos[2]] & L1[fa_pos[3]])
                ^ (L1[fa_pos[4]] & ir[r])
                ^ k[2 * r]
            )
            fb = (
                L2[fb_pos[0]]
                ^ L2[fb_pos[1]]
                ^ (L2[fb_pos[2]] & L2[fb_pos[3]])
                ^ (L2[fb_pos[4]] & L2[fb_pos[5]])
                ^ k[2 * r + 1]
            )

            # shift left (towards higher index), dropping MSB (last element)
            L1 = [fb, *L1[:-1]]
            L2 = [fa, *L2[:-1]]

    # recombine
    out = 0
    for i in range(l1 - 1, -1, -1):
        out = (out << 1) | L1[i]
    for i in range(l2 - 1, -1, -1):
        out = (out << 1) | L2[i]
    return out


class KATAN_CVL:
    r"""
    The CiVerLy implementation of the KATAN block cipher family.

    KATAN is an efficient block cipher designed by De Cannière, Dunkelman and
    Rechberger. It operates on three block sizes (32, 48 and 64 bits) and uses
    a LFSR-based key schedule together with two nonlinear register updates per
    round.

    This implementation is built as an ``SBoxCipher`` and therefore supports
    bitwise MILP and SAT modeling. The constructor accepts either a total
    number of rounds ``R`` or an explicit 1-based round range ``(start, end)``
    for sliceable analysis.

    EXAMPLES:

    Encrypt with the three variants (verified against the reference
    implementation)::

        sage: from civerly.cipher_implementations.katan import KATAN_CVL, reference_katan_encrypt
        sage: from civerly.util import int_to_vec, vec_to_int
        sage: key = 0x0123456789abcdef0123  # 80-bit example key
        sage: c32 = KATAN_CVL(variant=32, R=10, key=key)
        sage: pt32 = 0x12345678
        sage: vec_to_int(c32(int_to_vec(pt32, 32))) == reference_katan_encrypt(32, pt32, key, 10)
        True
        sage: vec_to_int(c32(int_to_vec(pt32, 32))) == 0xdb31e2cd
        True
        sage: c48 = KATAN_CVL(variant=48, R=8, key=key)
        sage: pt48 = 0x123456789abc
        sage: vec_to_int(c48(int_to_vec(pt48, 48))) == reference_katan_encrypt(48, pt48, key, 8)
        True
        sage: vec_to_int(c48(int_to_vec(pt48, 48))) == 0x51873abc9a78
        True
        sage: c64 = KATAN_CVL(variant=64, R=6, key=key)
        sage: pt64 = 0x0123456789abcdef
        sage: vec_to_int(c64(int_to_vec(pt64, 64))) == reference_katan_encrypt(64, pt64, key, 6)
        True
        sage: vec_to_int(c64(int_to_vec(pt64, 64))) == 0x15ff052f37bc14f0
        True

    Slicing by explicit round range yields the same result as the full cipher
    and can be composed. ``R`` and ``(start, end)`` are mutually exclusive::

        sage: full = KATAN_CVL(variant=32, R=10, key=key)
        sage: sliced = KATAN_CVL(variant=32, start=1, end=10, key=key)
        sage: vec_to_int(full(int_to_vec(pt32, 32))) == vec_to_int(sliced(int_to_vec(pt32, 32)))
        True
        sage: mid = vec_to_int(KATAN_CVL(variant=32, start=1, end=5, key=key)(int_to_vec(pt32, 32)))
        sage: mid == 0x46dacf16
        True
        sage: ct = vec_to_int(KATAN_CVL(variant=32, start=6, end=10, key=key)(int_to_vec(mid, 32)))
        sage: ct == vec_to_int(full(int_to_vec(pt32, 32)))
        True
        sage: ct == 0xdb31e2cd
        True
        sage: KATAN_CVL(variant=32, R=10, start=1, end=10, key=key)  # doctest: +IGNORE_EXCEPTION_DETAIL
        Traceback (most recent call last):
            ...
        ValueError: R cannot be combined with an explicit (start, end) range
        sage: KATAN_CVL(variant=32, start=1, key=key)  # doctest: +IGNORE_EXCEPTION_DETAIL
        Traceback (most recent call last):
            ...
        ValueError: end must be provided when start is given
        sage: KATAN_CVL(variant=32, end=10, key=key)  # doctest: +IGNORE_EXCEPTION_DETAIL
        Traceback (most recent call last):
            ...
        ValueError: start must be provided when end is given

    TESTS::

    SAT modeling does not require external minimizers for KATAN's tiny
    S-boxes, because the ``LOGICAL_COND`` encoding enumerates all possible
    transitions directly. This allows us to reproduce the 71-round differential
    trail with weight 30 from https://eprint.iacr.org/2012/401::

        sage: from civerly.cipher_implementations.katan import KATAN_CVL
        sage: from civerly.model_options import *
        sage: from civerly.util import suppress_output
        sage: import tempfile
        sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat
        ....:   c = KATAN_CVL(variant=32, R=71, key=0)
        ....:   model_options = MODEL_OPTIONS(
        ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:     optimization=OPTIMIZATION.SAT,
        ....:     granularity=GRANULARITY.BITWISE,
        ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
        ....:     logic_minimizer=ESPRESSO_CVL(),
        ....:     sat_solver=CRYPTOMINISAT_CVL(),
        ....:     path=Path(tmpdir))
        ....:   c.analyse(model_options)
        1399 variables and 3293 clauses were written to ...
        30

    Bitwise MILP modeling is also supported.  The following example is tagged
    as optional because it requires an external MILP solver::

        sage: from civerly.cipher_implementations.katan import KATAN_CVL
        sage: from civerly.model_options import *
        sage: from civerly.solvers import SCIP_CVL
        sage: from civerly.util import suppress_output
        sage: import tempfile
        sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
        ....:   c = KATAN_CVL(variant=32, R=15, key=0)
        ....:   model_options = MODEL_OPTIONS(
        ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:     optimization=OPTIMIZATION.MILP,
        ....:     granularity=GRANULARITY.BITWISE,
        ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
        ....:     milp_solver=SCIP_CVL(),
        ....:     path=Path(tmpdir))
        ....:   c.analyse(model_options)
        ....:   trail = c.get_trail(model_options)
        ....:   "Unnamed Component" not in str(trail)
        447 variables and 636 constraints were written to ...
        2
        True
    """

    def __init__(self, variant=32, R=254, start=None, end=None, key=0, name=None):
        r"""
        Build a KATAN cipher instance.

        INPUT:

            - ``variant`` -- integer; The block size of KATAN. It is required
              that ``variant`` is one of ``{32, 48, 64}``.

            - ``R`` -- integer; Number of rounds. Defaults to 254.

            - ``start`` -- integer (optional); First round of a slice (1-based).
              Must be provided together with ``end`` and is mutually exclusive
              with ``R``.

            - ``end`` -- integer (optional); Last round of a slice (1-based).
              Must be provided together with ``start``.

            - ``key`` -- integer (optional); The 80-bit master key. Defaults to
              0.

            - ``name`` -- string (optional); The name of the cipher.
        """
        if variant not in PARAMS:
            raise ValueError("Unsupported KATAN variant")

        if start is not None and end is None:
            raise ValueError("end must be provided when start is given")
        if end is not None and start is None:
            raise ValueError("start must be provided when end is given")
        if start is not None and end is not None and R != 254:
            raise ValueError("R cannot be combined with an explicit (start, end) range")

        params = PARAMS[variant]
        l1_len = params["l1"]
        l2_len = params["l2"]
        block_size = l1_len + l2_len

        if name is None:
            if start is not None:
                name = f"KATAN{variant}-r{start}-{end}"
            else:
                name = f"KATAN{variant}"

        rounds = range(R) if start is None else range(start - 1, end)

        # The key schedule and IR stream are defined over the full execution
        # up to ``end`` (round indices are 1-based externally), so derive the
        # required number of stream bits from ``end``.
        stream_end = end if end is not None else R

        key_stream = _key_bits(key, stream_end)
        ir_stream = _ir_bits(stream_end)

        cipher = SBoxCipher(block_size, block_size, name=name)

        # Each register is tracked as a list of ``(node, bit)`` sources indexed
        # by register bit position (0 = least significant). Shifting a register
        # is then a mere relabelling, so each step only adds the ``fa`` and
        # ``fb`` S-boxes to the graph. In the state vector, bit 0 is the most
        # significant bit of L1, followed by L1's lower bits and then L2.
        L1 = [(cipher.IN, l1_len - 1 - i) for i in range(l1_len)]
        L2 = [(cipher.IN, block_size - 1 - i) for i in range(l2_len)]

        for r in rounds:
            # all steps of a round use the same key and IR bits
            fa_sbox = _fa_sbox(ir_stream[r], key_stream[2 * r])
            fb_sbox = _fb_sbox(key_stream[2 * r + 1])
            for s in range(params["steps"]):
                prefix = f"KATAN{variant}-r{r}-s{s}"
                fa = cipher.add_subcipher(
                    SBox_CVL(fa_sbox, name=f"{prefix}-fa"),
                    [(L1[p][0], (L1[p][1], i)) for i, p in enumerate(params["fa"])],
                )
                fb = cipher.add_subcipher(
                    SBox_CVL(fb_sbox, name=f"{prefix}-fb"),
                    [(L2[p][0], (L2[p][1], i)) for i, p in enumerate(params["fb"])],
                )
                # shift towards the MSB, dropping it
                L1 = [(fb, 0), *L1[:-1]]
                L2 = [(fa, 0), *L2[:-1]]

        cipher.add_output(
            [(node, (bit, l1_len - 1 - i)) for i, (node, bit) in enumerate(L1)]
            + [(node, (bit, block_size - 1 - i)) for i, (node, bit) in enumerate(L2)]
        )
        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
