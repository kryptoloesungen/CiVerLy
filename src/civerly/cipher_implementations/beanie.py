from numbers import Integral

from sage.crypto.sbox import SBox
from sage.matrix.constructor import Matrix as matrix
from sage.matrix.special import block_matrix, identity_matrix
from sage.rings.finite_rings.finite_field_constructor import GF

from civerly.aeslike import AESlike
from civerly.cipher import Cipher
from civerly.cipher_implementations.base import CipherImplementation_CVL
from civerly.component import (
    XOR_CVL,
    ConstXOR_CVL,
    LinearLayer_CVL,
    PermuteLayer_CVL,
    RoundkeyXOR_CVL,
    SBox_CVL,
)
from civerly.keyschedule import KeySchedule
from civerly.sboxcipher import SBoxCipher
from civerly.util import int_to_vec, vec_to_int

# ---------------------------------------------------------------------------
# BEANIE tweak-key schedule
# ---------------------------------------------------------------------------

_SBOX = (0, 4, 2, 11, 10, 12, 9, 8, 5, 15, 13, 3, 7, 1, 6, 14)

# Round constants of the tweak-key schedule (the left 64-bit half of every
# constant is zero, so only the right half is listed).
_ROUND_CONSTANTS = (
    0x0000000000000000,
    0x13198A2E03707344,
    0xA4093822299F31D0,
    0x082EFA98EC4E6C89,
    0x452821E638D01377,
    0xBE5466CF34E90C6C,
    0x7EF84F78FD955CB1,
    0x85840851F1AC43AA,
    0xC882D32F25323C54,
    0x64A51195E0E3610D,
)

_MASK64 = 0xFFFFFFFFFFFFFFFF


def _to_int128(value):
    r"""
    Convert a 128-bit integer or a pair ``(left, right)`` of 64-bit integers
    (``left`` being the low half) into a 128-bit integer.
    """
    if isinstance(value, Integral):  # also covers Sage integers
        return int(value) & ((1 << 128) - 1)
    try:
        left, right = value
    except Exception as exc:
        raise ValueError(
            "master_key and tweak must be 128-bit integers or pairs of 64-bit integers"
        ) from exc
    return (int(left) & _MASK64) | ((int(right) & _MASK64) << 64)


def _prince_m_matrix(shift):
    r"""
    Return the :math:`16 \times 16` binary matrix of the PRINCE block
    :math:`\hat{M}^{(0)}` (``shift=0``) or :math:`\hat{M}^{(1)}` (``shift=1``)
    in the MSB-first bit order of :func:`civerly.util.int_to_vec`.
    """
    masks = (0x7, 0xB, 0xD, 0xE)
    blocks = [
        [
            matrix.diagonal(
                GF(2), [(masks[(i + j + shift) % 4] >> (3 - b)) & 1 for b in range(4)]
            )
            for j in range(4)
        ]
        for i in range(4)
    ]
    return block_matrix(GF(2), blocks, subdivide=False)


class BEANIE_KeySchedule_CVL(KeySchedule):
    def __init__(self, R=5, tweak=0, name="BEANIE-KeySchedule"):
        r"""
        The BEANIE tweak-key schedule as a CiVerLy DAG.

        Takes a 128-bit master key and derives the :math:`R+1` 32-bit round
        keys of :class:`BEANIE_CVL` (normal mode, ``R`` rounds) for the fixed
        128-bit ``tweak``. The tweak is processed together with the key by
        ``R`` rounds of a PRINCE-like 128-bit permutation, and the round keys
        are linear combinations of the four 32-bit words of the result.

        INPUT:

            - ``R`` -- integer (default: ``5``); number of encryption rounds
              of the cipher the round keys are used for (:math:`3 \le R \le 9`).

            - ``tweak`` -- integer or pair of 64-bit integers (default: ``0``);
              the 128-bit tweak. A pair ``(left, right)`` stands for the
              integer ``left + 2^64 * right``.

            - ``name`` -- string (default: ``"BEANIE-KeySchedule"``); the name
              of the key schedule.

        The master key passed to the key schedule is a 128-bit integer or,
        like the tweak, a pair of 64-bit integers. The output is the list of
        :math:`R+1` round keys (round key 0 first) in the order of
        ``BEANIE_CVL._rk_components``, the last one being the final whitening
        key.

        EXAMPLES:

        Reproduce the round keys of the official test vector (Table 15,
        ``rks1``)::

            sage: from civerly.cipher_implementations.beanie import (
            ....:   BEANIE_KeySchedule_CVL)
            sage: ks = BEANIE_KeySchedule_CVL(R=5, tweak=(0, 0))
            sage: rks = ks((0, 0))
            sage: print(" ".join(f"{k:08x}" for k in rks))
            beedff0f f8a29afc 9369ab08 7391f5d3 464f65f3 e0f85edb
            sage: ks(0) == BEANIE_KeySchedule_CVL()(0) == rks
            True
            sage: len(BEANIE_KeySchedule_CVL(R=3)(0))
            4
            sage: ks.input_length, ks.output_length
            (128, 192)

        Use it as the key schedule of :class:`BEANIE_CVL`::

            sage: from civerly.cipher_implementations.beanie import (
            ....:   BEANIE_CVL, BEANIE_KeySchedule_CVL)
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: beanie = BEANIE_CVL(
            ....:   R=5, key_schedule=BEANIE_KeySchedule_CVL(R=5), key=0)
            sage: hex(vec_to_int(beanie(int_to_vec(0x00000000, 32))))
            '0xda46f4d3'

        TESTS::

            sage: from civerly.cipher_implementations.beanie import (
            ....:   BEANIE_KeySchedule_CVL)
            sage: BEANIE_KeySchedule_CVL(R=2)
            Traceback (most recent call last):
            ...
            ValueError: the BEANIE key schedule supports 3 <= R <= 9, got R=2
            sage: BEANIE_KeySchedule_CVL(tweak="t")
            Traceback (most recent call last):
            ...
            ValueError: master_key and tweak must be 128-bit integers or pairs ...
        """
        if not 3 <= R <= 9:
            raise ValueError(f"the BEANIE key schedule supports 3 <= R <= 9, got R={R}")
        tweak = _to_int128(tweak)
        super().__init__(128, 32 * (R + 1), name=name)
        self._R = R
        self._tweak = tweak

        # State layout (MSB first): right half (bits 0..63) | left half
        # (bits 64..127), i.e. the 128-bit integer ``right * 2^64 + left``.
        # The master key and the tweak use the same layout.
        # First key addition: state = K ^ T.
        node = self.add_subcipher(
            ConstXOR_CVL(128, tweak, name="Tweak"),
            [(self.IN, (i, i)) for i in range(128)],
        )
        for r in range(R):
            node = self.add_subcipher(
                self._make_round(r), [(node, (i, i)) for i in range(128)]
            )
            node = self.add_subcipher(
                XOR_CVL(128, name=f"KeyAdd{r + 1}"),
                [(node, (i, i)) for i in range(128)]
                + [(self.IN, (i, 128 + i)) for i in range(128)],
            )
        node = self.add_subcipher(
            ConstXOR_CVL(128, _ROUND_CONSTANTS[R] << 64, name=f"RC{R}"),
            [(node, (i, i)) for i in range(128)],
        )

        # Key expansion: the 32-bit words (MSB first) of the scheduled
        # tweak-key are W[0] = bits 64..95, W[1] = bits 96..127,
        # W[2] = bits 0..31, W[3] = bits 32..63. Round keys 0..3 are the
        # words, round keys 4..9 are XORs of pairs of words.
        word_offsets = [64, 96, 0, 32]
        xor_pairs = [(0, 1), (2, 3), (0, 2), (1, 3), (0, 3), (1, 2)]
        output_edges = []
        for k in range(R + 1):
            if k < 4:
                src, off = node, word_offsets[k]
            else:
                a, b = xor_pairs[k - 4]
                src = self.add_subcipher(
                    XOR_CVL(32, name=f"RK{k}"),
                    [(node, (word_offsets[a] + i, i)) for i in range(32)]
                    + [(node, (word_offsets[b] + i, 32 + i)) for i in range(32)],
                )
                off = 0
            output_edges += [(src, (off + i, 32 * k + i)) for i in range(32)]
        self.add_output(output_edges)

    @staticmethod
    def _make_round(r):
        r"""
        Round ``r`` of the tweak-key schedule (without the following key
        addition) as an ``SBoxCipher(128, 128)``:

            RC -> SBoxes -> PRINCE M' -> PRINCE ShiftRows -> Feistel -> Shuffle
        """
        step = SBoxCipher(128, 128, name=f"TKS-round{r}")

        node_rc = step.add_subcipher(
            ConstXOR_CVL(128, _ROUND_CONSTANTS[r] << 64, name=f"RC{r}"),
            [(step.IN, (i, i)) for i in range(128)],
        )

        sbox = SBox_CVL(SBox(_SBOX), name="SBox")
        sb_nodes = [
            step.add_subcipher(sbox, [(node_rc, (4 * j + i, i)) for i in range(4)])
            for j in range(32)
        ]

        # PRINCE M' on each 64-bit half: the four 16-bit columns (MSB first)
        # are multiplied with M^(0), M^(1), M^(1), M^(0).
        m_0 = LinearLayer_CVL(_prince_m_matrix(0), name="M0")
        m_1 = LinearLayer_CVL(_prince_m_matrix(1), name="M1")
        m_nodes = [
            step.add_subcipher(
                (m_0, m_1, m_1, m_0)[c % 4],
                [(sb_nodes[4 * c + i // 4], (i % 4, i)) for i in range(16)],
            )
            for c in range(8)
        ]

        # PRINCE ShiftRows on each half: nibble row ``row`` of the 16-bit
        # columns is rotated by ``row`` columns (integer bit b -> b + 16 row).
        shift_perm = []
        for p in range(128):
            b = 63 - p % 64
            row = 3 - (b % 16) // 4
            shift_perm.append(64 * (p // 64) + 63 - (b + 16 * row) % 64)
        node_shift = step.add_subcipher(
            PermuteLayer_CVL(shift_perm, name="ShiftRows"),
            [(m_nodes[i // 16], (i % 16, i)) for i in range(128)],
        )

        # Feistel on the 32-bit words (w3, w2, w1, w0) (MSB first):
        # (w3, w2, w1, w0) -> (w3 ^ w2, w1, w1 ^ w0, w3).
        node_x_right = step.add_subcipher(
            XOR_CVL(32, name="Feistel_R"),
            [(node_shift, (i, i)) for i in range(64)],
        )
        node_x_left = step.add_subcipher(
            XOR_CVL(32, name="Feistel_L"),
            [(node_shift, (64 + i, i)) for i in range(64)],
        )

        # Nibble shuffle between and within the two halves.
        shuffle_perm = [None] * 128
        for b in range(128):
            half, col, row = b // 64, (b % 64) // 16, 3 - (b % 16) // 4
            if row == 1:
                half, col = (half, col + 2) if col < 2 else (1 - half, col - 2)
            elif row == 2:
                half = 1 - half
            elif row == 3:
                half, col = (half, col - 2) if col >= 2 else (1 - half, col + 2)
            dest = 64 * half + 16 * col + b % 16
            shuffle_perm[127 - b] = 127 - dest
        node_shuffle = step.add_subcipher(
            PermuteLayer_CVL(shuffle_perm, name="Shuffle"),
            [(node_x_right, (i, i)) for i in range(32)]
            + [(node_shift, (64 + i, 32 + i)) for i in range(32)]
            + [(node_x_left, (i, 64 + i)) for i in range(32)]
            + [(node_shift, (i, 96 + i)) for i in range(32)],
        )
        step.add_output([(node_shuffle, (i, i)) for i in range(128)])
        return step

    def eval(self, master_key):
        r"""
        Expand ``master_key`` into the list of :math:`R+1` round-key integers.

        INPUT:

            - ``master_key`` -- integer or pair of 64-bit integers; the
              128-bit master key.

        OUTPUT: list of :math:`R+1` 32-bit integers, round key 0 first.
        """
        bits = Cipher.eval(self, int_to_vec(_to_int128(master_key), 128))
        return [
            vec_to_int(bits[32 * i : 32 * (i + 1)])
            for i in range(self.output_length // 32)
        ]


class BEANIE_CVL(CipherImplementation_CVL, AESlike):
    def __init__(
        self,
        R=None,
        key_schedule=None,
        key=None,
        name="BEANIE",
        rl=None,
        rr=None,
    ):
        r"""
        The CiVerLy implementation of BEANIE.

        BEANIE is a 32-bit block cipher with an AES-like structure operating on
        a :math:`4 \times 2` state of 4-bit nibbles.

        INPUT:

            - ``R`` -- integer (default: ``5``); Number of encryption rounds.
              Must not be given in U-shape mode, where the number of rounds
              is ``rl + rr``.

            - ``key_schedule`` -- callable or
              :class:`civerly.keyschedule.KeySchedule` (optional); Key
              schedule used to derive round keys from ``key`` via
              ``set_round_keys``. Pass a :class:`BEANIE_KeySchedule_CVL`
              instance (with the same ``R`` and the desired ``tweak``) to use
              the real BEANIE tweak-key schedule, or
              :class:`civerly.keyschedule.DefaultKeySchedule_CVL` to pass
              explicit round keys (32 bits each, :math:`R+1` of them, the
              last one being the final whitening key). In U-shape mode it
              expects the :math:`rl+1` round keys of the left branch followed
              by the :math:`rr+1` round keys of the right branch (a branch
              with zero rounds has no round keys). Defaults to ``None`` (no
              key schedule, all-zero round keys).

            - ``key`` -- integer, pair of 64-bit integers or list of integers
              (optional); The 128-bit master key passed to ``key_schedule``,
              immediately expanded and injected via ``set_round_keys`` when
              both are given. Has no effect when ``key_schedule`` is ``None``.
              When using :class:`civerly.keyschedule.DefaultKeySchedule_CVL`,
              this is the list of round keys (round key 0 first).

            - ``name`` -- string (default: ``"BEANIE"``); The name of the
              cipher. A U-shape cipher gets the suffix ``-U-{rl}-{rr}``.

            - ``rl`` -- integer (optional); Number of rounds for the left
              (encryption) branch in the U-shape attack. If provided together
              with ``rr``, the cipher is assembled as a U-shape
              :math:`E^{-1}_{K,T'} \circ E_{K,T}`.

            - ``rr`` -- integer (optional); Number of rounds for the right
              (decryption) branch in the U-shape attack.

        This cipher is "plug-and-play" usable, i.e. it can be directly used
        when imported.

        EXAMPLES:

        Encrypt a message (for verifying the implementation)::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: beanie = BEANIE_CVL(R=5)
            sage: hex(vec_to_int(beanie(int_to_vec(0x12345678, 32))))
            '0x27a35219'

        Test with non-zero round keys, passed via
        :class:`civerly.keyschedule.DefaultKeySchedule_CVL`::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rks = [
            ....:   0x01234567, 0x89abcdef, 0xfedcba98,
            ....:   0x76543210, 0x88888888, 0x88888888
            ....: ]
            sage: beanie = BEANIE_CVL(
            ....:   R=5, key_schedule=DefaultKeySchedule_CVL(32, 6), key=rks)
            sage: hex(vec_to_int(beanie(int_to_vec(0x00000000, 32))))
            '0xf05a49f1'
            sage: hex(vec_to_int(beanie(int_to_vec(0xabcdef01, 32))))
            '0x8dd221be'

        Derive round keys from a master key / tweak pair with the BEANIE
        tweak-key schedule::

            sage: from civerly.cipher_implementations.beanie \
            ....:   import BEANIE_CVL, BEANIE_KeySchedule_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: beanie = BEANIE_CVL(
            ....:     R=5, key_schedule=BEANIE_KeySchedule_CVL(R=5, tweak=(0, 0)),
            ....:     key=(0, 0))
            sage: hex(vec_to_int(beanie(int_to_vec(0x00000000, 32))))
            '0xda46f4d3'
            sage: beanie = BEANIE_CVL(
            ....:     R=5, key_schedule=BEANIE_KeySchedule_CVL(), key=0)
            sage: hex(vec_to_int(beanie(int_to_vec(0x00000000, 32))))
            '0xda46f4d3'

        U-shape form with one round on each branch (the round keys of the
        left branch are followed by those of the right branch)::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rks_left = [0x01234567, 0x89abcdef]
            sage: rks_right = [0xfedcba98, 0x76543210]
            sage: beanie_u = BEANIE_CVL(
            ....:   rl=1, rr=1, key_schedule=DefaultKeySchedule_CVL(32, 4),
            ....:   key=rks_left + rks_right)
            sage: hex(vec_to_int(beanie_u(int_to_vec(0x12345678, 32))))
            '0xcfe08ba5'
            sage: beanie_u.name, beanie_u.R
            ('BEANIE-U-1-1', 2)

        U-shape form with two left and one right round::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rks_left = [0x01234567, 0x89abcdef, 0xfedcba98]
            sage: rks_right = [0x76543210, 0x11111111]
            sage: beanie_u = BEANIE_CVL(
            ....:   rl=2, rr=1, key_schedule=DefaultKeySchedule_CVL(32, 5),
            ....:   key=rks_left + rks_right)
            sage: hex(vec_to_int(beanie_u(int_to_vec(0x12345678, 32))))
            '0x458728b0'

        U-shape form with two rounds on each branch::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rks_left = [0x01234567, 0x89abcdef, 0xfedcba98]
            sage: rks_right = [0x76543210, 0x11111111, 0x22222222]
            sage: beanie_u = BEANIE_CVL(
            ....:   rl=2, rr=2, key_schedule=DefaultKeySchedule_CVL(32, 6),
            ....:   key=rks_left + rks_right)
            sage: hex(vec_to_int(beanie_u(int_to_vec(0x12345678, 32))))
            '0x3f8b64ed'

        TESTS:

        Verify with official test vectors (Table 15)::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: ks = DefaultKeySchedule_CVL(32, 6)
            sage: rks1 = [
            ....:   0xbeedff0f, 0xf8a29afc, 0x9369ab08,
            ....:   0x7391f5d3, 0x464f65f3, 0xe0f85edb
            ....: ]
            sage: beanie = BEANIE_CVL(R=5, key_schedule=ks, key=rks1)
            sage: hex(vec_to_int(beanie(int_to_vec(0x00000000, 32))))
            '0xda46f4d3'
            sage: rks2 = [
            ....:   0x93061e07, 0x87607a4d, 0xd7d11b34,
            ....:   0xb1769b2e, 0x1466644a, 0x66a7801a
            ....: ]
            sage: beanie.set_round_keys(rks2)
            sage: hex(vec_to_int(beanie(int_to_vec(0x1841938a, 32))))
            '0x92c2fea'

        Single-round trace::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: beanie = BEANIE_CVL(R=1)
            sage: hex(vec_to_int(beanie(int_to_vec(0x12345678, 32))))
            '0x49b5c28a'

        ``R`` cannot be combined with the U-shape parameters::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: BEANIE_CVL(R=5, rl=2, rr=2)
            Traceback (most recent call last):
            ...
            ValueError: R must not be given in U-shape mode, use rl and rr instead

        Model the cipher with MILP (differential, wordwise, branch number)::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: beanie = BEANIE_CVL(R=3)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
            ....:     milp_solver=SCIP_CVL(),
            ....:     path=Path(tmpdir))
            ....:   beanie.analyse(model_options)
            532 variables and 549 constraints were written to '...'
            8

        Three rounds of BEANIE have at least 8 active S-boxes. As the maximal
        differential probability of the S-box is :math:`2^{-2}`, this implies
        that the best 3-round differential trail has probability at most
        :math:`2^{-16}`, which is tight (see the SAT example below).

        Model the cipher with MILP (differential, bitwise). Solving the
        bitwise MILP is expensive, hence only two rounds are modeled here::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: beanie = BEANIE_CVL(R=2)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip  # long time
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:     milp_solver=SCIP_CVL(),
            ....:     path=Path(tmpdir))
            ....:   beanie.analyse(model_options)
            Using existing file ..., make sure it is up to date!
            1616 variables and 1713 constraints were written to '...'
            10

        Model the cipher with SAT (differential, bitwise)::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: beanie = BEANIE_CVL(R=3)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            ....:   beanie.analyse(model_options)
            ....:   trail = str(beanie.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            Using existing file ..., make sure it is up to date!
            2184 variables and 8457 clauses were written to '...'
            16
        """
        u_shape_mode = (rl is not None) or (rr is not None)

        if u_shape_mode and R is not None:
            raise ValueError(
                "R must not be given in U-shape mode, use rl and rr instead"
            )

        if u_shape_mode:
            if rl is None:
                rl = 0
            if rr is None:
                rr = 0
            R = rl + rr
            name = f"{name}-U-{rl}-{rr}"
        else:
            if R is None:
                R = 5

        super().__init__(4, 4, 2, R=R, key_schedule=key_schedule, key=key, name=name)

        # BEANIE S-box
        sbox = SBox_CVL(SBox(_SBOX), name="SBox")

        # S-box layer (8 S-boxes in parallel)
        sboxlayer = AESlike(4, 4, 2, name="SBoxLayer")
        for i in range(8):
            node = sboxlayer.add_subcipher(sbox, [(sboxlayer.IN, (i, 0))])
            sboxlayer.add_output([(node, (0, i))])

        # ShiftRows: rows 1 and 3 are rotated left by 1
        shiftrows = PermuteLayer_CVL(
            [0, 5, 2, 7, 4, 1, 6, 3], word_coarseness=4, name="ShiftRows"
        )

        # MixColumns: GF(2^4) MDS matrix with primitive polynomial x^4 + x + 1
        # Build per-nibble binary multiplication matrices
        mul2 = matrix(
            GF(2),
            [
                [0, 0, 0, 1],
                [1, 0, 0, 1],
                [0, 1, 0, 0],
                [0, 0, 1, 0],
            ],
        )
        mul1 = identity_matrix(GF(2), 4)
        mul4 = mul2 * mul2
        mul8 = mul2 * mul2 * mul2
        mul9 = mul8 + mul1
        muld = mul8 + mul4 + mul1
        mulf = mul8 + mul4 + mul2 + mul1

        # The matrix below is constructed for LSB-first order, then conjugated
        # by a full bit-reversal to match the MSB-first convention of int_to_vec.
        mix_matrix_lsb = block_matrix(
            GF(2),
            [
                [mul2, mul1, muld, mul1],
                [mul1, mul4, mul9, muld],
                [mul1, mulf, mul4, mul1],
                [mul9, mul1, mul1, mul2],
            ],
            subdivide=False,
        )

        P16 = matrix(GF(2), 16, 16)
        for i in range(16):
            P16[i, 15 - i] = 1
        mix_matrix = P16 * mix_matrix_lsb * P16

        mixcolumn = LinearLayer_CVL(
            mix_matrix,
            branch_number_differential=5,
            branch_number_linear=5,
            name="MixColumn",
        )

        # Full round: KeyAdd -> SBox -> ShiftRows -> MixColumns
        key_add = RoundkeyXOR_CVL(32, const=0x0, name="KeyAdd")
        beanie_round = AESlike(4, 4, 2, name="BEANIE-round")
        node_rk = beanie_round.add_subcipher(
            key_add, [(beanie_round.IN, (i, i)) for i in range(8)]
        )
        node_s = beanie_round.add_subcipher(
            sboxlayer, [(node_rk, (i, i)) for i in range(8)]
        )
        node_p = beanie_round.add_subcipher(
            shiftrows, [(node_s, (i, i)) for i in range(8)]
        )
        for j in range(2):
            node_mix = beanie_round.add_subcipher(
                mixcolumn, [(node_p, (i + 4 * j, i)) for i in range(4)]
            )
            beanie_round.add_output([(node_mix, (i, i + 4 * j)) for i in range(4)])

        # Last round: KeyAdd -> SBox -> ShiftRows (no MixColumns)
        beanie_last = AESlike(4, 4, 2, name="BEANIE-last")
        node_rk_last = beanie_last.add_subcipher(
            key_add, [(beanie_last.IN, (i, i)) for i in range(8)]
        )
        node_s = beanie_last.add_subcipher(
            sboxlayer, [(node_rk_last, (i, i)) for i in range(8)]
        )
        node_p = beanie_last.add_subcipher(
            shiftrows, [(node_s, (i, i)) for i in range(8)]
        )
        beanie_last.add_output([(node_p, (i, i)) for i in range(8)])

        if not u_shape_mode:
            # Assemble the R-round cipher; the round keys are the R round
            # keys of the rounds followed by the final whitening key.
            rk_components = []
            node = self.IN

            # Full rounds (all but the last round of the cipher)
            for _ in range(self.R - 1):
                node = self.add_subcipher(
                    beanie_round, [(node, (i, i)) for i in range(8)]
                )
                rk_components.append(self.nodes[node].nodes[node_rk])

            # Last round (without MixColumns) and final key addition
            node = self.add_subcipher(beanie_last, [(node, (i, i)) for i in range(8)])
            rk_components.append(self.nodes[node].nodes[node_rk_last])
            node = self.add_subcipher(key_add, [(node, (i, i)) for i in range(8)])
            rk_components.append(self.nodes[node])

            self.add_output([(node, (i, i)) for i in range(8)])
            self._rk_components = rk_components
        else:
            # Build U-shape cipher: E^{-1}_{K,T'} \circ E_{K,T}
            # Inverse S-box layer
            sbox_inv = SBox_CVL(sbox.S.inverse(), name="SBox_inv")
            sboxlayer_inv = AESlike(4, 4, 2, name="SBoxLayer_inv")
            for i in range(8):
                node = sboxlayer_inv.add_subcipher(
                    sbox_inv, [(sboxlayer_inv.IN, (i, 0))]
                )
                sboxlayer_inv.add_output([(node, (0, i))])

            # Inverse last block: KeyAdd -> ShiftRows -> SBox_inv -> KeyAdd
            # (corresponds to the inverse of the last encryption round)
            beanie_inv_last = AESlike(4, 4, 2, name="BEANIE-inv-last")
            node_rk_inv_first = beanie_inv_last.add_subcipher(
                key_add, [(beanie_inv_last.IN, (i, i)) for i in range(8)]
            )
            node_p_inv = beanie_inv_last.add_subcipher(
                shiftrows, [(node_rk_inv_first, (i, i)) for i in range(8)]
            )
            node_s_inv = beanie_inv_last.add_subcipher(
                sboxlayer_inv, [(node_p_inv, (i, i)) for i in range(8)]
            )
            node_rk_inv_second = beanie_inv_last.add_subcipher(
                key_add, [(node_s_inv, (i, i)) for i in range(8)]
            )
            beanie_inv_last.add_output([(node_rk_inv_second, (i, i)) for i in range(8)])

            # Inverse round block: MixColumns -> ShiftRows -> SBox_inv -> KeyAdd
            beanie_inv_round = AESlike(4, 4, 2, name="BEANIE-inv-round")
            node_mix0 = beanie_inv_round.add_subcipher(
                mixcolumn, [(beanie_inv_round.IN, (i, i)) for i in range(4)]
            )
            node_mix1 = beanie_inv_round.add_subcipher(
                mixcolumn, [(beanie_inv_round.IN, (i + 4, i)) for i in range(4)]
            )
            node_p_inv = beanie_inv_round.add_subcipher(
                shiftrows,
                [(node_mix0, (i, i)) for i in range(4)]
                + [(node_mix1, (i, i + 4)) for i in range(4)],
            )
            node_s_inv = beanie_inv_round.add_subcipher(
                sboxlayer_inv, [(node_p_inv, (i, i)) for i in range(8)]
            )
            node_rk_inv_round = beanie_inv_round.add_subcipher(
                key_add, [(node_s_inv, (i, i)) for i in range(8)]
            )
            beanie_inv_round.add_output([(node_rk_inv_round, (i, i)) for i in range(8)])

            # Assemble the U-shape cipher. Round keys: rl+1 of the left branch,
            # followed by rr+1 of the right branch.
            rks_left = [None] * (rl + 1)
            rks_right = [None] * (rr + 1)
            node = self.IN

            # Left branch: rl rounds of encryption
            for r in range(rl - 1):
                node = self.add_subcipher(
                    beanie_round, [(node, (i, i)) for i in range(8)]
                )
                rks_left[r] = self.nodes[node].nodes[node_rk]
            if rl > 0:
                node = self.add_subcipher(
                    beanie_last, [(node, (i, i)) for i in range(8)]
                )
                rks_left[rl - 1] = self.nodes[node].nodes[node_rk_last]
                node = self.add_subcipher(key_add, [(node, (i, i)) for i in range(8)])
                rks_left[rl] = self.nodes[node]

            # Right branch: rr rounds of decryption
            if rr > 0:
                node = self.add_subcipher(
                    beanie_inv_last, [(node, (i, i)) for i in range(8)]
                )
                rks_right[rr] = self.nodes[node].nodes[node_rk_inv_first]
                rks_right[rr - 1] = self.nodes[node].nodes[node_rk_inv_second]
                for r in range(rr - 2, -1, -1):
                    node = self.add_subcipher(
                        beanie_inv_round, [(node, (i, i)) for i in range(8)]
                    )
                    rks_right[r] = self.nodes[node].nodes[node_rk_inv_round]

            self.add_output([(node, (i, i)) for i in range(8)])

            # A branch with zero rounds has no round key components.
            self._rk_components = [rk for rk in rks_left + rks_right if rk is not None]

        if key_schedule is not None and key is not None:
            self.set_round_keys(key)
