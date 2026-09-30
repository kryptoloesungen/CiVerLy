from sage.crypto.sbox import SBox
from sage.matrix.constructor import Matrix as matrix
from sage.matrix.special import block_matrix, identity_matrix
from sage.rings.finite_rings.finite_field_constructor import GF

from civerly.aeslike import AESlike
from civerly.component import (
    LinearLayer_CVL,
    PermuteLayer_CVL,
    RoundkeyXOR_CVL,
    SBox_CVL,
)

# ---------------------------------------------------------------------------
# Helpers for the BEANIE tweak-key schedule
# ---------------------------------------------------------------------------

_SBOX = (0, 4, 2, 11, 10, 12, 9, 8, 5, 15, 13, 3, 7, 1, 6, 14)

_ROUND_CONSTANTS = (
    (0x0, 0x0000000000000000),
    (0x0, 0x13198A2E03707344),
    (0x0, 0xA4093822299F31D0),
    (0x0, 0x082EFA98EC4E6C89),
    (0x0, 0x452821E638D01377),
    (0x0, 0xBE5466CF34E90C6C),
    (0x0, 0x7EF84F78FD955CB1),
    (0x0, 0x85840851F1AC43AA),
    (0x0, 0xC882D32F25323C54),
    (0x0, 0x64A51195E0E3610D),
)


def _sbox64(state):
    output = 0
    for shift in range(0, 64, 4):
        output |= _SBOX[(state >> shift) & 0xF] << shift
    return output & 0xFFFFFFFFFFFFFFFF


def _prince_m_0(column):
    c0 = (column >> 12) & 0xF
    c1 = (column >> 8) & 0xF
    c2 = (column >> 4) & 0xF
    c3 = column & 0xF
    return (
        (((c0 & 0x7) ^ (c1 & 0xB) ^ (c2 & 0xD) ^ (c3 & 0xE)) << 12)
        | (((c0 & 0xB) ^ (c1 & 0xD) ^ (c2 & 0xE) ^ (c3 & 0x7)) << 8)
        | (((c0 & 0xD) ^ (c1 & 0xE) ^ (c2 & 0x7) ^ (c3 & 0xB)) << 4)
        | (((c0 & 0xE) ^ (c1 & 0x7) ^ (c2 & 0xB) ^ (c3 & 0xD)) << 0)
    ) & 0xFFFF


def _prince_m_1(column):
    c0 = (column >> 12) & 0xF
    c1 = (column >> 8) & 0xF
    c2 = (column >> 4) & 0xF
    c3 = column & 0xF
    return (
        (((c0 & 0xB) ^ (c1 & 0xD) ^ (c2 & 0xE) ^ (c3 & 0x7)) << 12)
        | (((c0 & 0xD) ^ (c1 & 0xE) ^ (c2 & 0x7) ^ (c3 & 0xB)) << 8)
        | (((c0 & 0xE) ^ (c1 & 0x7) ^ (c2 & 0xB) ^ (c3 & 0xD)) << 4)
        | (((c0 & 0x7) ^ (c1 & 0xB) ^ (c2 & 0xD) ^ (c3 & 0xE)) << 0)
    ) & 0xFFFF


def _prince_m(state):
    left, right = state
    left_columns = [
        left & 0xFFFF,
        (left >> 16) & 0xFFFF,
        (left >> 32) & 0xFFFF,
        (left >> 48) & 0xFFFF,
    ]
    right_columns = [
        right & 0xFFFF,
        (right >> 16) & 0xFFFF,
        (right >> 32) & 0xFFFF,
        (right >> 48) & 0xFFFF,
    ]
    left_columns = [
        _prince_m_0(left_columns[0]),
        _prince_m_1(left_columns[1]),
        _prince_m_1(left_columns[2]),
        _prince_m_0(left_columns[3]),
    ]
    right_columns = [
        _prince_m_0(right_columns[0]),
        _prince_m_1(right_columns[1]),
        _prince_m_1(right_columns[2]),
        _prince_m_0(right_columns[3]),
    ]
    left_out = 0
    right_out = 0
    for index, column in enumerate(left_columns):
        left_out |= column << (16 * index)
    for index, column in enumerate(right_columns):
        right_out |= column << (16 * index)
    return left_out & 0xFFFFFFFFFFFFFFFF, right_out & 0xFFFFFFFFFFFFFFFF


def _prince_shift(state):
    shifted = state & 0xF000F000F000F000
    for index in range(1, 4):
        row = state & (0xF000F000F000F000 >> (4 * index))
        shifted |= (row << (index * 16)) | (row >> (64 - index * 16))
    return shifted & 0xFFFFFFFFFFFFFFFF


def _feistel(state):
    left, right = state
    words = [
        left & 0xFFFFFFFF,
        (left >> 32) & 0xFFFFFFFF,
        right & 0xFFFFFFFF,
        (right >> 32) & 0xFFFFFFFF,
    ]
    new_words = [0, 0, 0, 0]
    new_words[0] = words[3]
    new_words[1] = words[1] ^ words[0]
    new_words[2] = words[1]
    new_words[3] = words[3] ^ words[2]
    return (
        ((new_words[1] & 0xFFFFFFFF) << 32) | (new_words[0] & 0xFFFFFFFF),
        ((new_words[3] & 0xFFFFFFFF) << 32) | (new_words[2] & 0xFFFFFFFF),
    )


def _tks_shift(state):
    left, right = state
    new_left = 0
    new_right = 0

    new_left |= left & 0xF000F000F000F000
    new_right |= right & 0xF000F000F000F000

    new_left |= ((left & 0x000000000F000F00) << 32) | (
        (right & 0x0F000F0000000000) >> 32
    )
    new_right |= ((right & 0x000000000F000F00) << 32) | (
        (left & 0x0F000F0000000000) >> 32
    )

    new_left |= right & 0x00F000F000F000F0
    new_right |= left & 0x00F000F000F000F0

    new_left |= ((left & 0x000F000F00000000) >> 32) | (
        (right & 0x00000000000F000F) << 32
    )
    new_right |= ((right & 0x000F000F00000000) >> 32) | (
        (left & 0x00000000000F000F) << 32
    )

    return new_left & 0xFFFFFFFFFFFFFFFF, new_right & 0xFFFFFFFFFFFFFFFF


def _tweak_key_schedule(key, tweak, rounds):
    if rounds == 0:
        return tweak

    left, right = tweak
    key_left, key_right = key

    for round_index in range(rounds):
        left ^= key_left
        right ^= key_right

        rc_left, rc_right = _ROUND_CONSTANTS[round_index]
        left ^= rc_left
        right ^= rc_right

        left = _sbox64(left)
        right = _sbox64(right)

        left, right = _prince_m((left, right))
        left = _prince_shift(left)
        right = _prince_shift(right)
        left, right = _feistel((left, right))
        left, right = _tks_shift((left, right))

    left ^= key_left
    right ^= key_right

    rc_left, rc_right = _ROUND_CONSTANTS[rounds]
    left ^= rc_left
    right ^= rc_right
    return left & 0xFFFFFFFFFFFFFFFF, right & 0xFFFFFFFFFFFFFFFF


def _key_expansion(key, nr_keys):
    if nr_keys <= 3:
        raise AssertionError

    left, right = key
    key_words = [
        (left >> 32) & 0xFFFFFFFF,
        left & 0xFFFFFFFF,
        (right >> 32) & 0xFFFFFFFF,
        right & 0xFFFFFFFF,
    ]

    round_keys = [0] * nr_keys
    round_keys[0] = key_words[0]
    round_keys[1] = key_words[1]
    round_keys[2] = key_words[2]
    round_keys[3] = key_words[3]

    if nr_keys > 4:
        round_keys[4] = round_keys[0] ^ round_keys[1]
    if nr_keys > 5:
        round_keys[5] = round_keys[2] ^ round_keys[3]
    if nr_keys > 6:
        round_keys[6] = round_keys[0] ^ round_keys[2]
    if nr_keys > 7:
        round_keys[7] = round_keys[1] ^ round_keys[3]
    if nr_keys > 8:
        round_keys[8] = round_keys[0] ^ round_keys[3]
    if nr_keys > 9:
        round_keys[9] = round_keys[1] ^ round_keys[2]

    return round_keys


def _split128(value):
    if isinstance(value, int):
        return (value & 0xFFFFFFFFFFFFFFFF, (value >> 64) & 0xFFFFFFFFFFFFFFFF)
    try:
        left, right = value
    except Exception as exc:
        raise ValueError(
            "master_key and tweak must be 128-bit integers or pairs of 64-bit integers"
        ) from exc
    return (int(left) & 0xFFFFFFFFFFFFFFFF, int(right) & 0xFFFFFFFFFFFFFFFF)


def _derive_round_keys(master_key, tweak, R):
    r"""
    Derive the BEANIE round keys from a 128-bit master key and tweak.

    INPUT:

        - ``master_key`` -- integer or pair of 64-bit integers.

        - ``tweak`` -- integer or pair of 64-bit integers.

        - ``R`` -- integer; number of encryption rounds.

    OUTPUT: list of ``R+1`` 32-bit round keys.
    """
    key = _split128(master_key)
    t_in = _split128(tweak)
    scheduled = _tweak_key_schedule(key, t_in, R)
    return _key_expansion(scheduled, R + 1)


class BEANIE_CVL:
    def __init__(
        self,
        R=None,
        start=None,
        end=None,
        rks=None,
        master_key=None,
        tweak=None,
        name=None,
        rl=None,
        rr=None,
        rks_right=None,
    ):
        r"""
        The CiVerLy implementation of BEANIE.

        BEANIE is a 32-bit block cipher with an AES-like structure operating on
        a :math:`4 \times 2` state of 4-bit nibbles.

        INPUT:

            - ``R`` -- integer (default: ``5``); Number of encryption rounds.
              Must not be given in U-shape mode, where the number of rounds
              is determined by ``rl`` and ``rr``.

            - ``start`` -- integer (optional); First round of the slice to
              build (1-indexed, absolute with respect to an ``R``-round cipher).
              Must be given together with ``end``.

            - ``end`` -- integer (optional); Last round of the slice to build
              (1-indexed, inclusive). Round ``R`` always contains the final
              whitening key addition.

            - ``rks`` -- list (optional); The round key values. Must have
              length :math:`R+1` (normal mode) or :math:`rl+1` (U-shape mode).
              Defaults to all zeros.

            - ``master_key`` -- 128-bit integer or pair of 64-bit integers
              (optional); The main key. If given, ``tweak`` must also be given
              and ``rks`` must not be given. The round keys are derived with
              the BEANIE tweak-key schedule. Not supported in U-shape mode.

            - ``tweak`` -- 128-bit integer or pair of 64-bit integers
              (optional); The 128-bit tweak used together with ``master_key``.

            - ``name`` -- string (optional); The name of the cipher.

            - ``rl`` -- integer (optional); Number of rounds for the left
              (encryption) branch in the U-shape attack. If provided together
              with ``rr``, the cipher is assembled as a U-shape
              :math:`E^{-1}_{K,T'} \circ E_{K,T}`.

            - ``rr`` -- integer (optional); Number of rounds for the right
              (decryption) branch in the U-shape attack.

            - ``rks_right`` -- list (optional); The round key values for the
              right branch in U-shape mode. Must have length :math:`rr+1`.
              Defaults to all zeros.

        This cipher is "plug-and-play" usable.

        EXAMPLES:

        Encrypt a message (for verifying the implementation)::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: beanie = BEANIE_CVL(R=5)
            sage: hex(vec_to_int(beanie(int_to_vec(0x12345678, 32))))
            '0x27a35219'

        Test with non-zero round keys::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rks = [
            ....:   0x01234567, 0x89abcdef, 0xfedcba98,
            ....:   0x76543210, 0x88888888, 0x88888888
            ....: ]
            sage: beanie = BEANIE_CVL(R=5, rks=rks)
            sage: hex(vec_to_int(beanie(int_to_vec(0x00000000, 32))))
            '0xf05a49f1'
            sage: hex(vec_to_int(beanie(int_to_vec(0xabcdef01, 32))))
            '0x8dd221be'

        Derive round keys from a master key / tweak pair::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: beanie = BEANIE_CVL(
            ....:     R=5, master_key=(0, 0), tweak=(0, 0))
            sage: hex(vec_to_int(beanie(int_to_vec(0x00000000, 32))))
            '0xda46f4d3'

        Slicing is absolute with respect to the full ``R``-round cipher. The
        output of a first slice can be chained into a second slice to reproduce
        the full encryption::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rks = [
            ....:   0x01234567, 0x89abcdef, 0xfedcba98,
            ....:   0x76543210, 0x88888888, 0x88888888
            ....: ]
            sage: beanie_full = BEANIE_CVL(R=5, rks=rks)
            sage: beanie_12 = BEANIE_CVL(R=5, start=1, end=2, rks=rks)
            sage: beanie_35 = BEANIE_CVL(R=5, start=3, end=5, rks=rks)
            sage: pt = int_to_vec(0xabcdef01, 32)
            sage: mid = beanie_12(pt)
            sage: vec_to_int(beanie_35(mid)) == vec_to_int(beanie_full(pt))
            True

        U-shape form with one round on each branch::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rks_left = [0x01234567, 0x89abcdef]
            sage: rks_right = [0xfedcba98, 0x76543210]
            sage: beanie_u = BEANIE_CVL(rl=1, rr=1, rks=rks_left,
            ....:                       rks_right=rks_right)
            sage: hex(vec_to_int(beanie_u(int_to_vec(0x12345678, 32))))
            '0xcfe08ba5'

        U-shape form with two left and one right round::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rks_left = [0x01234567, 0x89abcdef, 0xfedcba98]
            sage: rks_right = [0x76543210, 0x11111111]
            sage: beanie_u = BEANIE_CVL(rl=2, rr=1, rks=rks_left,
            ....:                       rks_right=rks_right)
            sage: hex(vec_to_int(beanie_u(int_to_vec(0x12345678, 32))))
            '0x458728b0'

        U-shape form with two rounds on each branch::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rks_left = [0x01234567, 0x89abcdef, 0xfedcba98]
            sage: rks_right = [0x76543210, 0x11111111, 0x22222222]
            sage: beanie_u = BEANIE_CVL(rl=2, rr=2, rks=rks_left,
            ....:                       rks_right=rks_right)
            sage: hex(vec_to_int(beanie_u(int_to_vec(0x12345678, 32))))
            '0x3f8b64ed'

        TESTS:

        Verify with official test vectors (Table 15)::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rks1 = [
            ....:   0xbeedff0f, 0xf8a29afc, 0x9369ab08,
            ....:   0x7391f5d3, 0x464f65f3, 0xe0f85edb
            ....: ]
            sage: beanie = BEANIE_CVL(R=5, rks=rks1)
            sage: hex(vec_to_int(beanie(int_to_vec(0x00000000, 32))))
            '0xda46f4d3'
            sage: rks2 = [
            ....:   0x93061e07, 0x87607a4d, 0xd7d11b34,
            ....:   0xb1769b2e, 0x1466644a, 0x66a7801a
            ....: ]
            sage: beanie = BEANIE_CVL(R=5, rks=rks2)
            sage: hex(vec_to_int(beanie(int_to_vec(0x1841938a, 32))))
            '0x92c2fea'

        Single-round trace::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: beanie = BEANIE_CVL(R=1)
            sage: hex(vec_to_int(beanie(int_to_vec(0x12345678, 32))))
            '0x49b5c28a'

        A one-round slice matches the first full round::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rks = [0x01234567, 0x89abcdef, 0xfedcba98]
            sage: full = BEANIE_CVL(R=1, rks=rks[:2])
            sage: slce = BEANIE_CVL(R=1, start=1, end=1, rks=rks[:2])
            sage: full(int_to_vec(0x12345678, 32)) == slce(int_to_vec(0x12345678, 32))
            True

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
        if name is None:
            name = "BEANIE"

        u_shape_mode = (rl is not None) or (rr is not None)

        if u_shape_mode and R is not None:
            raise ValueError(
                "R must not be given in U-shape mode, use rl and rr instead"
            )
        if R is None:
            R = 5

        # -------------------------------------------------------------------
        # Validate the round-range arguments.
        # -------------------------------------------------------------------
        if (start is not None) != (end is not None):
            raise ValueError("start and end must be provided together")

        if u_shape_mode and (start is not None or end is not None):
            raise ValueError("start/end slicing is not supported in U-shape mode")

        if start is not None:
            if not (1 <= start <= end <= R):
                raise ValueError("invalid start/end range for the given R")
        else:
            start = 1
            end = R

        # -------------------------------------------------------------------
        # Validate / derive the round keys.
        # -------------------------------------------------------------------
        if master_key is not None or tweak is not None:
            if u_shape_mode:
                raise ValueError("master_key/tweak not supported in U-shape mode")
            if rks is not None:
                raise ValueError("rks and master_key/tweak are mutually exclusive")
            if master_key is None or tweak is None:
                raise ValueError("master_key and tweak must be supplied together")
            rks = _derive_round_keys(master_key, tweak, R)

        if not u_shape_mode:
            if rks is None:
                rks = [0] * (R + 1)
            if len(rks) != R + 1:
                raise ValueError(f"rks must have length R+1 = {R + 1}, got {len(rks)}")
        else:
            if rl is None:
                rl = 0
            if rr is None:
                rr = 0
            if rks is None:
                rks = [0] * (rl + 1)
            if len(rks) != rl + 1:
                raise ValueError(
                    f"rks must have length rl+1 = {rl + 1}, got {len(rks)}"
                )
            if rks_right is None:
                rks_right = [0] * (rr + 1)
            if len(rks_right) != rr + 1:
                raise ValueError(
                    f"rks_right must have length rr+1 = {rr + 1}, got {len(rks_right)}"
                )

        # BEANIE S-box
        sbox = SBox_CVL(
            SBox([0, 4, 2, 11, 10, 12, 9, 8, 5, 15, 13, 3, 7, 1, 6, 14]), name="SBox"
        )

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
        key_add_last = RoundkeyXOR_CVL(32, const=0x0, name="KeyAdd")
        beanie_last = AESlike(4, 4, 2, name="BEANIE-last")
        node_rk_last = beanie_last.add_subcipher(
            key_add_last, [(beanie_last.IN, (i, i)) for i in range(8)]
        )
        node_s = beanie_last.add_subcipher(
            sboxlayer, [(node_rk_last, (i, i)) for i in range(8)]
        )
        node_p = beanie_last.add_subcipher(
            shiftrows, [(node_s, (i, i)) for i in range(8)]
        )
        beanie_last.add_output([(node_p, (i, i)) for i in range(8)])

        if not u_shape_mode:
            # Assemble the (possibly sliced) normal cipher
            if start != 1 or end != R:
                name = f"{name}-{start}-{end}"
            beanie_cipher = AESlike(4, 4, 2, name=name)
            node = beanie_cipher.IN

            # Full rounds (all but the last round of the cipher)
            for r in range(start - 1, min(end, R - 1)):
                beanie_round.nodes[node_rk].const = rks[r]
                node = beanie_cipher.add_subcipher(
                    beanie_round, [(node, (i, i)) for i in range(8)]
                )

            # Last round only if the slice reaches it
            if end == R:
                beanie_last.nodes[node_rk_last].const = rks[R - 1]
                node = beanie_cipher.add_subcipher(
                    beanie_last, [(node, (i, i)) for i in range(8)]
                )
                key_add_final = RoundkeyXOR_CVL(32, const=rks[R], name="KeyAdd")
                node = beanie_cipher.add_subcipher(
                    key_add_final, [(node, (i, i)) for i in range(8)]
                )

            beanie_cipher.add_output([(node, (i, i)) for i in range(8)])
            self.beanie_cipher = beanie_cipher
            return

        # Build U-shape cipher: E^{-1}_{K,T'} \circ E_{K,T}
        # Inverse S-box layer
        sbox_inv = SBox_CVL(sbox.S.inverse(), name="SBox_inv")
        sboxlayer_inv = AESlike(4, 4, 2, name="SBoxLayer_inv")
        for i in range(8):
            node = sboxlayer_inv.add_subcipher(sbox_inv, [(sboxlayer_inv.IN, (i, 0))])
            sboxlayer_inv.add_output([(node, (0, i))])

        # Inverse last block: KeyAdd -> ShiftRows -> SBox_inv -> KeyAdd
        # (corresponds to the inverse of the last encryption round)
        key_add_inv_first = RoundkeyXOR_CVL(32, const=0x0, name="KeyAdd")
        beanie_inv_last = AESlike(4, 4, 2, name="BEANIE-inv-last")
        node_rk_inv_first = beanie_inv_last.add_subcipher(
            key_add_inv_first, [(beanie_inv_last.IN, (i, i)) for i in range(8)]
        )
        node_p_inv = beanie_inv_last.add_subcipher(
            shiftrows, [(node_rk_inv_first, (i, i)) for i in range(8)]
        )
        node_s_inv = beanie_inv_last.add_subcipher(
            sboxlayer_inv, [(node_p_inv, (i, i)) for i in range(8)]
        )
        key_add_inv_second = RoundkeyXOR_CVL(32, const=0x0, name="KeyAdd")
        node_rk_inv_second = beanie_inv_last.add_subcipher(
            key_add_inv_second, [(node_s_inv, (i, i)) for i in range(8)]
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
        key_add_inv_round = RoundkeyXOR_CVL(32, const=0x0, name="KeyAdd")
        node_rk_inv_round = beanie_inv_round.add_subcipher(
            key_add_inv_round, [(node_s_inv, (i, i)) for i in range(8)]
        )
        beanie_inv_round.add_output([(node_rk_inv_round, (i, i)) for i in range(8)])

        # Assemble the U-shape cipher
        beanie_cipher = AESlike(4, 4, 2, name=f"{name}-U-{rl}-{rr}")
        node = beanie_cipher.IN

        # Left branch: rl rounds of encryption
        for r in range(rl - 1):
            beanie_round.nodes[node_rk].const = rks[r]
            node = beanie_cipher.add_subcipher(
                beanie_round, [(node, (i, i)) for i in range(8)]
            )
        if rl > 0:
            beanie_last.nodes[node_rk_last].const = rks[rl - 1]
            node = beanie_cipher.add_subcipher(
                beanie_last, [(node, (i, i)) for i in range(8)]
            )
            key_add_final_left = RoundkeyXOR_CVL(32, const=rks[rl], name="KeyAdd")
            node = beanie_cipher.add_subcipher(
                key_add_final_left, [(node, (i, i)) for i in range(8)]
            )

        # Right branch: rr rounds of decryption
        if rr > 0:
            beanie_inv_last.nodes[node_rk_inv_first].const = rks_right[rr]
            beanie_inv_last.nodes[node_rk_inv_second].const = rks_right[rr - 1]
            node = beanie_cipher.add_subcipher(
                beanie_inv_last, [(node, (i, i)) for i in range(8)]
            )
            for r in range(rr - 2, -1, -1):
                beanie_inv_round.nodes[node_rk_inv_round].const = rks_right[r]
                node = beanie_cipher.add_subcipher(
                    beanie_inv_round, [(node, (i, i)) for i in range(8)]
                )

        beanie_cipher.add_output([(node, (i, i)) for i in range(8)])
        self.beanie_cipher = beanie_cipher

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.beanie_cipher
