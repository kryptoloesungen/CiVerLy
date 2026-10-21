"""
KATAN implementation for CiVerLy.

Reference implementation and attribution: https://gist.github.com/raullenchai/2712516

This Python/Sage implementation was validated against the C reference
included in documentation/reference_implementation_katan.c. Consult the
original sources for licensing and full attribution.
"""

from sage.crypto.sbox import SBox
from sage.matrix.constructor import Matrix as matrix
from sage.rings.finite_rings.finite_field_constructor import GF

from civerly.cipher import Cipher
from civerly.cipher_implementations.base import CipherImplementation_CVL
from civerly.component import LinearLayer_CVL, RoundkeyXOR_CVL, SBox_CVL
from civerly.keyschedule import KeySchedule
from civerly.sboxcipher import SBoxCipher
from civerly.util import int_to_vec

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


def _fa_sbox(ir_bit):
    table = []
    for value in range(1 << 5):
        bits = [(value >> (4 - i)) & 1 for i in range(5)]
        output = bits[0] ^ bits[1] ^ (bits[2] & bits[3])
        if ir_bit:
            output ^= bits[4]
        table.append(output)
    return SBox(table)


def _fb_sbox():
    table = []
    for value in range(1 << 6):
        bits = [(value >> (5 - i)) & 1 for i in range(6)]
        output = bits[0] ^ bits[1] ^ (bits[2] & bits[3]) ^ (bits[4] & bits[5])
        table.append(output)
    return SBox(table)


class KATAN_KeySchedule_CVL(KeySchedule):
    r"""
    The KATAN key schedule as a CiVerLy DAG, producing the round keys in the
    order of the round-key components of :class:`KATAN_CVL`.

    KATAN expands the 80-bit master key ``k_0, ..., k_79`` (``k_0`` being the
    least significant bit) with the LFSR
    ``k_i = k_{i-80} + k_{i-61} + k_{i-50} + k_{i-13}``. In every step of
    round ``r`` (0-based), KATAN XORs the key bit ``k_{2r}`` into the output
    of ``f_a`` and ``k_{2r+1}`` into the output of ``f_b``.
    :class:`KATAN_CVL` models this with one 2-bit round-key XOR per step, so
    each round key is the 2-bit integer ``k_{2r} || k_{2r+1}`` (with
    ``k_{2r}`` as most significant bit). As all steps of a round use the same
    key bits, KATAN48 and KATAN64 (2 resp. 3 steps per round) repeat each
    round key 2 resp. 3 times.

    The key bits ``k_0, ..., k_79`` are taken directly from the master key.
    As the LFSR is linear over `GF(2)`, all further key bits
    ``k_80, ..., k_{2R-1}`` are computed by a single
    :class:`civerly.component.LinearLayer_CVL` on the master key. The
    repeated round keys of KATAN48/64 are wired as multiple output edges from
    the same key bits.

    INPUT:

        - ``variant`` -- integer (default: ``32``); the block size of KATAN,
          one of ``{32, 48, 64}``. Determines the number of steps per round.

        - ``R`` -- integer (default: ``254``); number of rounds, as in
          :class:`KATAN_CVL`.

        - ``name`` -- string (optional); the name of the key schedule.

    EXAMPLES::

        sage: from civerly.cipher_implementations.katan import (
        ....:   KATAN_KeySchedule_CVL)
        sage: ks = KATAN_KeySchedule_CVL()
        sage: ks(0x0123456789abcdef0123)[:6]
        [3, 0, 1, 0, 2, 0]
        sage: ks.input_length, ks.output_length, len(ks(0x0123))
        (80, 508, 254)
        sage: KATAN_KeySchedule_CVL(variant=48, R=3)(0x0123456789abcdef0123)
        [3, 3, 0, 0, 1, 1]
        sage: len(KATAN_KeySchedule_CVL(variant=64)(0x0))
        762

    Bits beyond the master key are produced by the LFSR::

        sage: KATAN_KeySchedule_CVL(R=41)(1)[-1]  # k_80 = k_0 = 1, k_81 = 0
        2
    """

    def __init__(self, variant=32, R=254, name=None):
        if variant not in PARAMS:
            raise ValueError("Unsupported KATAN variant")
        if not 0 < R <= 254:
            raise ValueError("Invalid number of rounds for KATAN")
        if name is None:
            name = f"KATAN{variant}-KeySchedule"
        steps = PARAMS[variant]["steps"]
        super().__init__(80, 2 * R * steps, name=name)
        self._R = R
        self._steps = steps

        # Source ``(node, bit)`` of each key bit k_0, ..., k_{2R-1}. In the
        # master-key vector, k_i is at position 79 - i (MSB first).
        sources = [(self.IN, 79 - i) for i in range(min(80, 2 * R))]
        if 2 * R > 80:
            # rows[i]: k_i as GF(2)-linear combination of the input positions
            rows = [[int(j == 79 - i) for j in range(80)] for i in range(80)]
            for i in range(80, 2 * R):
                rows.append(
                    [
                        a ^ b ^ c ^ d
                        for a, b, c, d in zip(
                            rows[i - 80],
                            rows[i - 61],
                            rows[i - 50],
                            rows[i - 13],
                            strict=False,
                        )
                    ]
                )
            lfsr = self.add_subcipher(
                LinearLayer_CVL(matrix(GF(2), rows[80:]), name=f"{name}-LFSR"),
                [(self.IN, (j, j)) for j in range(80)],
            )
            sources += [(lfsr, i) for i in range(2 * R - 80)]

        # round key of step s in round r: k_{2r} || k_{2r+1}
        self.add_output(
            [
                (node, (bit, 2 * (r * steps + s) + b))
                for r in range(R)
                for s in range(steps)
                for b, (node, bit) in enumerate(sources[2 * r : 2 * r + 2])
            ]
        )

    def eval(self, master_key):
        r"""
        Expand the 80-bit ``master_key`` into the list of ``R * steps`` 2-bit
        round-key integers, in the order of the round-key components of
        :class:`KATAN_CVL`.

        INPUT:

            - ``master_key`` -- integer; the 80-bit master key.

        OUTPUT: list of ``R * steps`` integers in ``{0, 1, 2, 3}``.
        """
        bits = Cipher.eval(self, int_to_vec(master_key, 80))
        return [
            (int(bits[2 * c]) << 1) | int(bits[2 * c + 1])
            for c in range(self._R * self._steps)
        ]


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


class KATAN_CVL(CipherImplementation_CVL, SBoxCipher):
    r"""
    The CiVerLy implementation of the KATAN block cipher family.

    KATAN is an efficient block cipher designed by De Cannière, Dunkelman and
    Rechberger. It operates on three block sizes (32, 48 and 64 bits) and uses
    a LFSR-based key schedule together with two nonlinear register updates per
    round.

    This implementation is built as an ``SBoxCipher`` and therefore supports
    bitwise MILP and SAT modeling. Reduced-round versions (always starting
    with the first round) are obtained via ``R``.

    The key bits are XORed into the outputs of ``f_a`` and ``f_b`` by one 2-bit
    round-key XOR per step (see :class:`KATAN_KeySchedule_CVL`), so the round keys
    can be injected via ``set_round_keys``.

    EXAMPLES:

    Encrypt with the three variants (verified against the reference
    implementation)::

        sage: from civerly.cipher_implementations.katan import (
        ....:   KATAN_CVL, KATAN_KeySchedule_CVL, reference_katan_encrypt)
        sage: from civerly.util import int_to_vec, vec_to_int
        sage: key = 0x0123456789abcdef0123  # 80-bit example key
        sage: c32 = KATAN_CVL(
        ....:   variant=32, R=10, key_schedule=KATAN_KeySchedule_CVL(32, 10),
        ....:   key=key)
        sage: pt32 = 0x12345678
        sage: vec_to_int(c32(int_to_vec(pt32, 32))) == \
        ....:   reference_katan_encrypt(32, pt32, key, 10)
        True
        sage: vec_to_int(c32(int_to_vec(pt32, 32))) == 0xdb31e2cd
        True
        sage: ks48 = KATAN_KeySchedule_CVL(variant=48, R=8)
        sage: c48 = KATAN_CVL(variant=48, R=8, key_schedule=ks48, key=key)
        sage: pt48 = 0x123456789abc
        sage: vec_to_int(c48(int_to_vec(pt48, 48))) == \
        ....:   reference_katan_encrypt(48, pt48, key, 8)
        True
        sage: vec_to_int(c48(int_to_vec(pt48, 48))) == 0x51873abc9a78
        True
        sage: ks64 = KATAN_KeySchedule_CVL(variant=64, R=6)
        sage: c64 = KATAN_CVL(variant=64, R=6, key_schedule=ks64, key=key)
        sage: pt64 = 0x0123456789abcdef
        sage: vec_to_int(c64(int_to_vec(pt64, 64))) == \
        ....:   reference_katan_encrypt(64, pt64, key, 6)
        True
        sage: vec_to_int(c64(int_to_vec(pt64, 64))) == 0x15ff052f37bc14f0
        True

    Explicit round keys can be passed via
    :class:`civerly.keyschedule.DefaultKeySchedule_CVL` (one 2-bit round key
    per step, i.e. ``R`` of them for KATAN32)::

        sage: from civerly.keyschedule import DefaultKeySchedule_CVL
        sage: rks = KATAN_KeySchedule_CVL(R=10)(key)
        sage: c32 = KATAN_CVL(
        ....:   variant=32, R=10, key_schedule=DefaultKeySchedule_CVL(2, 10),
        ....:   key=rks)
        sage: hex(vec_to_int(c32(int_to_vec(pt32, 32))))
        '0xdb31e2cd'

    Without key schedule, all round keys are zero::

        sage: c32 = KATAN_CVL(variant=32, R=10)
        sage: vec_to_int(c32(int_to_vec(pt32, 32))) == \
        ....:   reference_katan_encrypt(32, pt32, 0, 10)
        True

    Reduced-round versions with a matching key schedule::

        sage: c32 = KATAN_CVL(
        ....:   variant=32, R=5, key_schedule=KATAN_KeySchedule_CVL(R=5), key=key)
        sage: vec_to_int(c32(int_to_vec(pt32, 32))) == 0x46dacf16
        True

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
        ....:   c = KATAN_CVL(variant=32, R=71)
        ....:   model_options = MODEL_OPTIONS(
        ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:     optimization=OPTIMIZATION.SAT,
        ....:     granularity=GRANULARITY.BITWISE,
        ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
        ....:     logic_minimizer=ESPRESSO_CVL(),
        ....:     sat_solver=CRYPTOMINISAT_CVL(),
        ....:     path=Path(tmpdir))
        ....:   c.analyse(model_options)
        1683 variables and 3861 clauses were written to ...
        30

    Bitwise MILP modeling is also supported.  The following example is tagged
    as optional because it requires an external MILP solver::

        sage: from civerly.cipher_implementations.katan import KATAN_CVL
        sage: from civerly.model_options import *
        sage: from civerly.solvers import SCIP_CVL
        sage: from civerly.util import suppress_output
        sage: import tempfile
        sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
        ....:   c = KATAN_CVL(variant=32, R=15)
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
        507 variables and 696 constraints were written to ...
        2
        True
    """

    def __init__(
        self,
        variant=32,
        R=254,
        key_schedule=None,
        key=None,
        name=None,
    ):
        r"""
        Build a KATAN cipher instance.

        INPUT:

            - ``variant`` -- integer (default: ``32``); The block size of
              KATAN. It is required that ``variant`` is one of
              ``{32, 48, 64}``.

            - ``R`` -- integer (default: ``254``); Number of rounds, starting
              with the first round.

            - ``key_schedule`` -- callable or
              :class:`civerly.keyschedule.KeySchedule` (optional); Key
              schedule used to derive round keys from ``key`` via
              ``set_round_keys``. Pass
              ``KATAN_KeySchedule_CVL(variant, R)`` (same ``variant`` and
              ``R``) to use the real KATAN key schedule, or
              :class:`civerly.keyschedule.DefaultKeySchedule_CVL` to pass
              explicit round keys (2 bits each, one per step, i.e.
              ``R * steps`` of them with ``steps`` = 1, 2, 3 for KATAN32, 48,
              64). Defaults to ``None`` (no key schedule, all-zero round
              keys).

            - ``key`` -- integer or list of integers (optional); The 80-bit
              master key passed to ``key_schedule``, immediately expanded and
              injected via ``set_round_keys`` when both are given. Has no
              effect when ``key_schedule`` is ``None``. When using
              :class:`civerly.keyschedule.DefaultKeySchedule_CVL`, this is the
              list of round keys (round key 0 first).

            - ``name`` -- string (optional); The name of the cipher. Defaults
              to ``"KATAN<variant>"``.

        This cipher is "plug-and-play" usable, i.e. it can be directly used
        when imported.
        """
        if variant not in PARAMS:
            raise ValueError("Unsupported KATAN variant")

        if name is None:
            name = f"KATAN{variant}"

        params = PARAMS[variant]
        l1_len = params["l1"]
        l2_len = params["l2"]
        block_size = l1_len + l2_len

        super().__init__(
            block_size, block_size, R=R, key_schedule=key_schedule, key=key, name=name
        )

        ir_stream = _ir_bits(self.R)
        fb_sbox = _fb_sbox()

        # Each register is tracked as a list of ``(node, bit)`` sources indexed
        # by register bit position (0 = least significant). Shifting a register
        # is then a mere relabelling, so each step only adds the ``fa`` and
        # ``fb`` S-boxes and the 2-bit round-key XOR on their outputs to the
        # graph. In the state vector, bit 0 is the most significant bit of L1,
        # followed by L1's lower bits and then L2.
        L1 = [(self.IN, l1_len - 1 - i) for i in range(l1_len)]
        L2 = [(self.IN, block_size - 1 - i) for i in range(l2_len)]

        rk_nodes = []
        for r in range(self.R):
            # all steps of a round use the same key and IR bits
            fa_sbox = _fa_sbox(ir_stream[r])
            for s in range(params["steps"]):
                prefix = f"KATAN{variant}-r{r}-s{s}"
                fa = self.add_subcipher(
                    SBox_CVL(fa_sbox, name=f"{prefix}-fa"),
                    [(L1[p][0], (L1[p][1], i)) for i, p in enumerate(params["fa"])],
                )
                fb = self.add_subcipher(
                    SBox_CVL(fb_sbox, name=f"{prefix}-fb"),
                    [(L2[p][0], (L2[p][1], i)) for i, p in enumerate(params["fb"])],
                )
                # XOR k_{2r} into fa's and k_{2r+1} into fb's output
                rk = self.add_subcipher(
                    RoundkeyXOR_CVL(2, 0, name=f"{prefix}-rk"),
                    [(fa, (0, 0)), (fb, (0, 1))],
                )
                rk_nodes.append(rk)
                # shift towards the MSB, dropping it
                L1 = [(rk, 1), *L1[:-1]]
                L2 = [(rk, 0), *L2[:-1]]

        self.add_output(
            [(node, (bit, l1_len - 1 - i)) for i, (node, bit) in enumerate(L1)]
            + [(node, (bit, block_size - 1 - i)) for i, (node, bit) in enumerate(L2)]
        )

        self._rk_components = [self.nodes[n] for n in rk_nodes]

        if key_schedule is not None and key is not None:
            self.set_round_keys(key)
