r"""
Implementation of ARADI.

Aradi is a 128-bit SPN with four 32-bit state words. This implementation
follows the specification in the project documentation:

- a 4-bit S-box applied in parallel across the 32 bit positions,
- a word-wise linear layer on each 32-bit word,
- and a 128-bit round key added before each round plus a post-whitening key.
"""

from sage.crypto.sbox import SBox
from sage.matrix.constructor import Matrix as matrix
from sage.rings.finite_rings.finite_field_constructor import GF

from civerly.cipher_implementations.base import CipherImplementation_CVL
from civerly.component import (
    XOR_CVL,
    ConstXOR_CVL,
    LinearLayer_CVL,
    RotateLayer_CVL,
    RoundkeyXOR_CVL,
    SBox_CVL,
)
from civerly.keyschedule import KeySchedule
from civerly.sboxcipher import SBoxCipher
from civerly.util import int_to_vec

_MASK16 = (1 << 16) - 1
_MASK32 = (1 << 32) - 1


def _rol16(value, shift):
    """Rotate a 16-bit half-word left by ``shift`` bits."""
    shift %= 16
    value &= _MASK16
    return ((value << shift) | (value >> (16 - shift))) & _MASK16


def _aradi_sbox_table():
    """Build the 4-bit ARADI S-box truth table."""
    table = []
    for nibble in range(16):
        w = (nibble >> 3) & 1
        x = (nibble >> 2) & 1
        y = (nibble >> 1) & 1
        z = nibble & 1

        x = x ^ (w & y)
        z = z ^ (x & y)
        y = y ^ (w & z)
        w = w ^ (x & z)

        table.append((w << 3) | (x << 2) | (y << 1) | z)
    return table


def _aradi_linear_word_eval(word, a, b, c):
    """Evaluate ARADI's linear layer on one 32-bit word."""
    upper = (word >> 16) & _MASK16
    lower = word & _MASK16

    first = upper ^ _rol16(upper, a) ^ _rol16(lower, c)
    second = lower ^ _rol16(lower, a) ^ _rol16(upper, b)

    return ((first & _MASK16) << 16) | (second & _MASK16)


def _aradi_linear_word_matrix(a, b, c):
    """Return the binary matrix representation for one word transform."""
    rows = []
    for basis_index in range(32):
        basis = 1 << (31 - basis_index)
        rows.append(int_to_vec(_aradi_linear_word_eval(basis, a, b, c), 32))
    return matrix(GF(2), rows).transpose()


def _make_mix(a, b, name):
    r"""
    Word-pair mixing map ``M_{a,b}`` as a ``SBoxCipher(64, 64)``.

    Input ``x || y`` (two 32-bit words), output ``u || v`` with::

        u = (x <<< a) ^ y
        v = (y <<< b) ^ u

    ``M0 = M_{1,3}`` and ``M1 = M_{9,28}``.
    """
    mix = SBoxCipher(64, 64, name=name)
    node_rx = mix.add_subcipher(
        RotateLayer_CVL(32, a, name=f"ROL{a}"),
        [(mix.IN, (i, i)) for i in range(32)],
    )
    node_ry = mix.add_subcipher(
        RotateLayer_CVL(32, b, name=f"ROL{b}"),
        [(mix.IN, (32 + i, i)) for i in range(32)],
    )
    node_u = mix.add_subcipher(
        XOR_CVL(32, name="XOR_u"),
        [(node_rx, (i, i)) for i in range(32)]
        + [(mix.IN, (32 + i, 32 + i)) for i in range(32)],
    )
    node_v = mix.add_subcipher(
        XOR_CVL(32, name="XOR_v"),
        [(node_ry, (i, i)) for i in range(32)]
        + [(node_u, (i, 32 + i)) for i in range(32)],
    )
    mix.add_output(
        [(node_u, (i, i)) for i in range(32)]
        + [(node_v, (i, 32 + i)) for i in range(32)]
    )
    return mix


class ARADI_KeySchedule_CVL(KeySchedule):
    def __init__(self, R=16, name="ARADI-KeySchedule"):
        r"""
        ARADI key schedule as a CiVerLy DAG.

        Takes the 256-bit master key (eight 32-bit words ``K_0 || ... || K_7``,
        word 0 in the most significant bits) and expands it into the ``R + 1``
        128-bit round keys of :class:`ARADI_CVL` with ``R`` rounds, in
        ``_rk_components`` order (round keys ``0, ..., R - 1`` followed by the
        post-whitening key).

        The 256-bit key register is updated by ``R`` steps; step ``j``
        applies ``M0`` to word pairs ``(0, 1)`` and ``(4, 5)``, ``M1`` to
        pairs ``(2, 3)`` and ``(6, 7)``, the word permutation ``P_{j mod 2}``
        and XORs ``j`` into word 7. Key ``k`` is taken from the register after
        ``k`` steps: its first four words for even ``k``, its last four words
        for odd ``k``. For ``R = 16`` the last key is the post-whitening key of
        the specification; for reduced ``R`` the last key is the ``R``-th
        key of the full schedule.

        INPUT:

            - ``R`` -- integer (default: ``16``); Number of rounds of the
              ARADI instance, same meaning as in :class:`ARADI_CVL`.

            - ``name`` -- string (default: ``"ARADI-KeySchedule"``); The name
              of the key schedule.

        EXAMPLES::

            sage: from civerly.cipher_implementations.aradi import (
            ....:   ARADI_KeySchedule_CVL)
            sage: ks = ARADI_KeySchedule_CVL()
            sage: key = [
            ....:   0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C,
            ....:   0x13121110, 0x17161514, 0x1B1A1918, 0x1F1E1D1C,
            ....: ]
            sage: rks = ks(key)
            sage: len(rks)
            17
            sage: hex(rks[0]), hex(rks[16])
            ('0x3020100070605040b0a09080f0e0d0c', '0xa443053b69322a8ee8abfb4f41cf0ca8')
            sage: ks(
            ....:   0x03020100070605040B0A09080F0E0D0C13121110171615141B1A19181F1E1D1C
            ....: ) == rks
            True
            sage: ARADI_KeySchedule_CVL(R=2)(key) == rks[:3]
            True

        TESTS:

        The full key schedule against the reference test vector::

            sage: from civerly.cipher_implementations.aradi import (
            ....:   ARADI_KeySchedule_CVL)
            sage: ks = ARADI_KeySchedule_CVL(16)
            sage: (ks.input_length, ks.output_length)
            (256, 2176)
            sage: k = 0x03020100070605040B0A09080F0E0D0C13121110171615141B1A19181F1E1D1C
            sage: for rk in ks(k):
            ....:     print(f'{rk:032x}')
            03020100070605040b0a09080f0e0d0c
            313237342b2c2d2a89829f94eaddccfb
            1918131249484342bfb2b5b8efe2e5e8
            93d8dd9649bbf10212918d0e2caf0292
            7c795e5b6e0a4a2f708952ab0fb51eb7
            73be37f3b12de15c6d10261a63fa1fb1
            30e1a56556518eba38a4dc7043b62b6b
            6ff94bf4a1525d49960d690af40ac5e6
            652b43fa7ea0caa18356eca6eed8d0ca
            1e8816b8eaf40402bf1911dbd2ed83c3
            2aed0767d7e429720ddcac43e0ce34bd
            e587db6fd93a728ee7a7904354e47c4c
            5deafddf1235c451b94205971bc4fb83
            f95881fca9cbae8e266a00c264230546
            cc0fab2e5b7aad7732495539b022810a
            71c5c0468ab9aa02d8fb0856b7dfa119
            a443053b69322a8ee8abfb4f41cf0ca8
            sage: ks([0] * 7)
            Traceback (most recent call last):
            ...
            ValueError: ARADI master key must contain 8 words, got 7
            sage: ks(1 << 256)
            Traceback (most recent call last):
            ...
            ValueError: ARADI master key does not fit into 256 bits: ...
        """
        super().__init__(256, 128 * (R + 1), name=name)
        self.R = R

        m0 = _make_mix(1, 3, name="M0")
        m1 = _make_mix(9, 28, name="M1")

        # Round key 0 is the first half of the master key.
        output_edges = [(self.IN, (i, i)) for i in range(128)]
        node = self.IN
        for j in range(R):
            node = self.add_subcipher(
                self._make_step(j, m0, m1),
                [(node, (i, i)) for i in range(256)],
            )
            # Key j + 1: last four words for odd j + 1, first four otherwise.
            offset = 128 if (j + 1) % 2 == 1 else 0
            output_edges += [
                (node, (offset + i, 128 * (j + 1) + i)) for i in range(128)
            ]
        self.add_output(output_edges)

    @staticmethod
    def _make_step(j, m0, m1):
        r"""
        One key-register update step ``j`` as a ``SBoxCipher(256, 256)``:
        mix the word pairs with ``M0``/``M1``, permute the words with
        ``P_{j mod 2}`` and XOR the counter ``j`` into word 7.
        """
        step = SBoxCipher(256, 256, name=f"KS-step-{j}")
        mixes = [
            step.add_subcipher(mix, [(step.IN, (64 * p + i, i)) for i in range(64)])
            for p, mix in enumerate([m0, m1, m0, m1])
        ]
        # Source of each mixed word t_0, ..., t_7 as (node, bit offset).
        words = [(mixes[w // 2], 32 * (w % 2)) for w in range(8)]

        # P_j: output word k takes mixed word perm[k].
        perm = [0, 2, 1, 3, 4, 6, 5, 7] if j % 2 == 0 else [0, 4, 2, 6, 1, 5, 3, 7]

        # Word 7 is fixed by both permutations; add the counter to it.
        node_c, off_c = words[perm[7]]
        node_ctr = step.add_subcipher(
            ConstXOR_CVL(32, j, name=f"XOR_ctr{j}"),
            [(node_c, (off_c + i, i)) for i in range(32)],
        )
        words_out = [words[perm[k]] for k in range(7)] + [(node_ctr, 0)]
        step.add_output(
            [
                (src, (off + i, 32 * k + i))
                for k, (src, off) in enumerate(words_out)
                for i in range(32)
            ]
        )
        return step

    def eval(self, master_key):
        r"""
        Expand ``master_key`` into a list of ``R + 1`` round-key integers.

        INPUT:

            - ``master_key`` -- integer or list of 8 integers; the 256-bit
              master key, either as a 256-bit integer whose most significant
              32 bits are word 0, or as eight 32-bit words.

        OUTPUT: list of ``R + 1`` integers, each a 128-bit round key
        ``w || x || y || z`` (round keys ``0, ..., R - 1``, then the
        post-whitening key).
        """
        from civerly.cipher import Cipher
        from civerly.util import vec_to_int

        if hasattr(master_key, "__iter__"):
            words = list(master_key)
            if len(words) != 8:
                raise ValueError(
                    f"ARADI master key must contain 8 words, got {len(words)}"
                )
            master_key = 0
            for i, word in enumerate(words):
                if not 0 <= word <= _MASK32:
                    raise ValueError(
                        f"Master key word {i} is out of 32-bit range: {word}"
                    )
                master_key = (master_key << 32) | int(word)
        if not 0 <= master_key < (1 << 256):
            raise ValueError(
                f"ARADI master key does not fit into 256 bits: {master_key}"
            )

        bits = Cipher.eval(self, int_to_vec(master_key, 256))
        return [
            vec_to_int(bits[128 * k : 128 * (k + 1)])
            for k in range(self.output_length // 128)
        ]


class ARADI_CVL(CipherImplementation_CVL, SBoxCipher):
    def __init__(
        self,
        R=16,
        key_schedule=None,
        key=None,
        name="ARADI",
    ):
        r"""
        The CiVerLy implementation of ARADI.

        ARADI is a 128-bit SPN with four 32-bit state words. The cipher
        is built as a layered DAG where each round is an explicit
        ``SBoxCipher`` subcipher, making round boundaries easy to
        identify for analysis tools.

        INPUT:

            - ``R`` -- integer (default: ``16``); Number of rounds, starting
              at round 0. The post-whitening key addition is always appended
              after the last round.

            - ``key_schedule`` -- callable or
              :class:`civerly.keyschedule.KeySchedule` (optional); Key
              schedule used to derive round keys from ``key`` via
              ``set_round_keys``. Pass an :class:`ARADI_KeySchedule_CVL`
              instance with the same ``R`` to use the real ARADI key schedule
              (for reduced ``R`` it yields the leading ``R + 1`` keys of the
              full schedule), or
              :class:`civerly.keyschedule.DefaultKeySchedule_CVL` to pass
              explicit 128-bit round keys: ``R + 1`` of them, one per round
              plus the post-whitening key. Defaults to ``None`` (no key
              schedule, all-zero round keys).

            - ``key`` -- list of integers or integer (optional); The 256-bit
              master key (eight 32-bit words, or a 256-bit integer) passed to
              ``key_schedule``, immediately expanded and injected via
              ``set_round_keys`` when both are given. Has no effect when
              ``key_schedule`` is ``None``. When using
              :class:`civerly.keyschedule.DefaultKeySchedule_CVL`, this is the
              list of round keys (round key 0 first, post-whitening key last).

            - ``name`` -- string (default: ``"ARADI"``); The name of the
              cipher.

        This cipher is "plug-and-play" usable, i.e. it can be directly used
        when imported.

        ROUND STRUCTURE:

            Each round is a named ``SBoxCipher`` subcipher wired as
            ``add-round-key -> S-box layer -> linear layer``.  The
            linear layer cycles through four variants ``L0``--``L3``
            with shift parameters ``(11,8,14)``, ``(10,9,11)``,
            ``(9,4,14)``, and ``(8,9,7)``.

            After the last round, a post-whitening key is added.

        TESTS:

        Test vector with explicit round keys, passed via
        :class:`civerly.keyschedule.DefaultKeySchedule_CVL`::

            sage: from civerly.cipher_implementations.aradi import ARADI_CVL
            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: # Round keys from the reference test vector
            sage: rks = [
            ....:   0x3020100070605040b0a09080f0e0d0c,
            ....:   0x313237342b2c2d2a89829f94eaddccfb,
            ....:   0x1918131249484342bfb2b5b8efe2e5e8,
            ....:   0x93d8dd9649bbf10212918d0e2caf0292,
            ....:   0x7c795e5b6e0a4a2f708952ab0fb51eb7,
            ....:   0x73be37f3b12de15c6d10261a63fa1fb1,
            ....:   0x30e1a56556518eba38a4dc7043b62b6b,
            ....:   0x6ff94bf4a1525d49960d690af40ac5e6,
            ....:   0x652b43fa7ea0caa18356eca6eed8d0ca,
            ....:   0x1e8816b8eaf40402bf1911dbd2ed83c3,
            ....:   0x2aed0767d7e429720ddcac43e0ce34bd,
            ....:   0xe587db6fd93a728ee7a7904354e47c4c,
            ....:   0x5deafddf1235c451b94205971bc4fb83,
            ....:   0xf95881fca9cbae8e266a00c264230546,
            ....:   0xcc0fab2e5b7aad7732495539b022810a,
            ....:   0x71c5c0468ab9aa02d8fb0856b7dfa119,
            ....:   0xa443053b69322a8ee8abfb4f41cf0ca8,
            ....: ]
            sage: aradi = ARADI_CVL(
            ....:   key_schedule=DefaultKeySchedule_CVL(128, 17), key=rks)
            sage: hex(vec_to_int(aradi(int_to_vec(0x0, 128))))
            '0x3f09abf400e3bd7403260defb7c53912'

        The same cipher, constructed from the master key with the real key
        schedule::

            sage: from civerly.cipher_implementations.aradi \
            ....:   import ARADI_KeySchedule_CVL
            sage: key = [
            ....:   0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C,
            ....:   0x13121110, 0x17161514, 0x1B1A1918, 0x1F1E1D1C,
            ....: ]
            sage: aradi_from_key = ARADI_CVL(
            ....:   key_schedule=ARADI_KeySchedule_CVL(), key=key)
            sage: hex(vec_to_int(aradi_from_key(int_to_vec(0x0, 128))))
            '0x3f09abf400e3bd7403260defb7c53912'
            sage: aradi_from_key.set_round_keys([0] * 8)
            sage: aradi_from_key(int_to_vec(0x0, 128)) == \
            ....:   ARADI_CVL(key_schedule=ARADI_KeySchedule_CVL(), key=0)(
            ....:     int_to_vec(0x0, 128))
            True

        A reduced-round instance uses the leading round keys of the full key
        schedule (the last of them acting as post-whitening key)::

            sage: aradi_red = ARADI_CVL(
            ....:   R=2, key_schedule=ARADI_KeySchedule_CVL(R=2), key=key)
            sage: len(aradi_red._rk_components)
            3
            sage: [c.const for c in aradi_red._rk_components] == \
            ....:   ARADI_KeySchedule_CVL()(key)[:3]
            True

        Analyse ARADI with MILP (matching https://eprint.iacr.org/2024/1324.pdf)::

            sage: # optional - scip # doctest: +ELLIPSIS
            ....: from civerly.cipher_implementations.aradi import ARADI_CVL
            ....: from civerly.model_options import *
            ....: aradi_small = ARADI_CVL(R=2)
            ....: import tempfile
            ....: from pathlib import Path
            ....: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=SCIP_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            ....:   aradi_small.analyse(model_options)
            ....:   trail = aradi_small.get_trail(model_options)
            ....:   all("Unnamed Component" not in str(node) for node in trail.children)
            Using existing file ..., make sure it is up to date!
            7872 variables and 9537 constraints were written to ...
            8
            True
        """
        super().__init__(128, 128, R=R, key_schedule=key_schedule, key=key, name=name)

        sbox = SBox_CVL(SBox(_aradi_sbox_table()), name="SBox")
        sbox_layer = SBoxCipher(128, 128, name="SBoxLayer")
        for bit_index in range(32):
            node = sbox_layer.add_subcipher(
                sbox,
                [
                    (sbox_layer.IN, (bit_index + 32 * word_index, word_index))
                    for word_index in range(4)
                ],
            )
            sbox_layer.add_output(
                [
                    (node, (word_index, bit_index + 32 * word_index))
                    for word_index in range(4)
                ]
            )

        linear_layers = []
        for round_index in range(4):
            a_values = [11, 10, 9, 8]
            b_values = [8, 9, 4, 9]
            c_values = [14, 11, 14, 7]

            linear_layer = SBoxCipher(128, 128, name=f"LinearLayer{round_index}")
            word_matrix = _aradi_linear_word_matrix(
                a_values[round_index],
                b_values[round_index],
                c_values[round_index],
            )
            word_component = LinearLayer_CVL(word_matrix, name=f"L{round_index}")
            for word_index in range(4):
                node = linear_layer.add_subcipher(
                    word_component,
                    [
                        (linear_layer.IN, (32 * word_index + bit_index, bit_index))
                        for bit_index in range(32)
                    ],
                )
                linear_layer.add_output(
                    [
                        (node, (bit_index, 32 * word_index + bit_index))
                        for bit_index in range(32)
                    ]
                )
            linear_layers.append(linear_layer)

        node = self.IN
        rk_nodes = []

        for round_index in range(self.R):
            round_cipher = SBoxCipher(128, 128, name=f"ARADI-round-{round_index}")
            rk = RoundkeyXOR_CVL(128, 0x0, name="RK")
            node_rk = round_cipher.add_subcipher(
                rk,
                [(round_cipher.IN, (bit_index, bit_index)) for bit_index in range(128)],
            )
            node_sbox = round_cipher.add_subcipher(
                sbox_layer,
                [(node_rk, (bit_index, bit_index)) for bit_index in range(128)],
            )
            node_linear = round_cipher.add_subcipher(
                linear_layers[round_index % 4],
                [(node_sbox, (bit_index, bit_index)) for bit_index in range(128)],
            )
            round_cipher.add_output(
                [(node_linear, (bit_index, bit_index)) for bit_index in range(128)]
            )

            node = self.add_subcipher(
                round_cipher,
                [(node, (bit_index, bit_index)) for bit_index in range(128)],
            )
            rk_nodes.append((node, node_rk))

        self._rk_components = [self.nodes[n].nodes[n_rk] for n, n_rk in rk_nodes]

        # Post-whitening key addition after the last round.
        post_rk = RoundkeyXOR_CVL(128, 0x0, name="PostRK")
        node = self.add_subcipher(
            post_rk, [(node, (bit_index, bit_index)) for bit_index in range(128)]
        )
        self._rk_components.append(self.nodes[node])

        self.add_output([(node, (bit_index, bit_index)) for bit_index in range(128)])

        if key_schedule is not None and key is not None:
            self.set_round_keys(key)
