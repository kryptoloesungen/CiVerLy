r"""
Implementation of ARADI.

Aradi is a 128-bit SPN with four 32-bit state words. This implementation
follows the specification in the project documentation:

- a 4-bit S-box applied in parallel across the 32 bit positions,
- a word-wise linear layer on each 32-bit word,
- and explicit 128-bit round keys for each round plus a post-add.
"""

from sage.crypto.sbox import SBox
from sage.matrix.constructor import Matrix as matrix
from sage.rings.finite_rings.finite_field_constructor import GF

from civerly.component import LinearLayer_CVL, RoundkeyXOR_CVL, SBox_CVL
from civerly.sboxcipher import SBoxCipher
from civerly.util import int_to_vec

_MASK16 = (1 << 16) - 1
_MASK32 = (1 << 32) - 1


def _rol32(value, shift):
    """Rotate a 32-bit word left by ``shift`` bits."""
    shift %= 32
    value &= _MASK32
    return ((value << shift) | (value >> (32 - shift))) & _MASK32


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


def _m0(x, y):
    s = _rol32(x, 1)
    return (s ^ y, _rol32(y, 3) ^ s ^ y)


def _m1(x, y):
    s = _rol32(x, 9)
    return (s ^ y, _rol32(y, 28) ^ s ^ y)


def _permute(state, j):
    state = list(state)
    if j % 2 == 0:
        state[1], state[2] = state[2], state[1]
        state[5], state[6] = state[6], state[5]
    else:
        state[1], state[4] = state[4], state[1]
        state[3], state[6] = state[6], state[3]
    return state


def _keyschedule_step(input_state, i):
    # Mix the four word pairs with M0/M1.
    t0, t1 = _m0(input_state[0], input_state[1])
    t2, t3 = _m1(input_state[2], input_state[3])
    t4, t5 = _m0(input_state[4], input_state[5])
    t6, t7 = _m1(input_state[6], input_state[7])
    mixed = [t0, t1, t2, t3, t4, t5, t6, t7]

    # Apply P_i and XOR the round counter into the last word.
    perm = _permute(mixed, i)
    perm[7] = (perm[7] ^ i) & _MASK32
    return perm


def _aradi_key_schedule(master_key):
    r"""
    Expand a 256-bit ARADI master key into 17 128-bit round keys.

    INPUT:

        - ``master_key`` -- list or tuple of 8 integers; The master key
          words, each fitting in 32 bits.

    OUTPUT: A list of 17 integers, each encoding one 128-bit round key
    as ``w || x || y || z`` in big-endian layout.
    """
    if len(master_key) != 8:
        raise ValueError(
            f"ARADI master key must contain 8 words, got {len(master_key)}"
        )

    # Validate range and convert to a mutable list of 32-bit words.
    key_state = []
    for i, word in enumerate(master_key):
        if not (0 <= word <= _MASK32):
            raise ValueError(f"Master key word {i} is out of 32-bit range: {word}")
        key_state.append(int(word) & _MASK32)

    # Generate the successive 8-word register states.
    states = [key_state]
    for i in range(1, 16, 2):
        ki = _keyschedule_step(states[-1], i - 1)
        ki2 = _keyschedule_step(ki, i)
        states.append(ki)
        states.append(ki2)

    # Extract round keys.  Even-indexed rounds use the first four words,
    # odd-indexed rounds the last four; the post-whitening key is the
    # first four words of the final register state.
    round_key_word_lists = [states[0][:4]]
    for i in range(1, 16, 2):
        round_key_word_lists.append(states[i][4:])
        round_key_word_lists.append(states[i + 1][:4])

    round_keys = []
    for words in round_key_word_lists:
        rk = (
            (words[0] & _MASK32) << 96
            | (words[1] & _MASK32) << 64
            | (words[2] & _MASK32) << 32
            | (words[3] & _MASK32)
        )
        round_keys.append(rk)

    return round_keys


class ARADI_CVL:
    def __init__(
        self,
        R=None,
        rks=None,
        key=None,
        name=None,
        round_start=0,
        round_end=None,
    ):
        r"""
        Implement ARADI in CiVerLy.

        ARADI is a 128-bit SPN with four 32-bit state words. The cipher
        is built as a layered DAG where each round is an explicit
        ``SBoxCipher`` subcipher, making round boundaries easy to
        identify for slicing and analysis tools.

        INPUT:

            - ``rks`` -- list (optional); Explicit 128-bit round keys.
              Must have length ``actual_rounds + 1`` for a slice ending at
              the cipher's final round, or ``actual_rounds`` otherwise.
              Mutually exclusive with ``key``.

            - ``key`` -- list (optional); The 256-bit ARADI master key as a
              list of eight 32-bit words.  The key schedule is expanded
              automatically to produce the round keys.  Mutually exclusive
              with ``rks``.

            - ``name`` -- string (optional); The name of the cipher.

            - ``round_start`` -- integer (optional, default ``0``); Index
              of the first round to include.  When this is not ``0``,
              ``round_end`` must be given and ``R`` must be ``None``.

            - ``round_end`` -- integer (optional, default ``None``); Index
               of the last round to include.  When given, ``R`` must be
               ``None`` and the number of rounds is computed as
               ``round_end - round_start + 1``.

             - ``R`` -- integer (optional); Number of rounds of the
               underlying full cipher.  Only used when ``round_start``
               or ``round_end`` is given, to decide whether the slice
               reaches the cipher's final round and therefore needs the
               post-whitening key addition.  Defaults to ``16`` both
               here and in non-slicing mode.

        ROUND STRUCTURE:

            Each round is a named ``SBoxCipher`` subcipher wired as
            ``add-round-key -> S-box layer -> linear layer``.  The
            linear layer cycles through four variants ``L0``--``L3``
            with shift parameters ``(11,8,14)``, ``(10,9,11)``,
            ``(9,4,14)``, and ``(8,9,7)``.

            The first round of the slice is just the ordinary round
            keyed with ``rks[round_index - round_start]``.  A
            post-whitening key addition is only appended when
            ``round_end`` equals the last round of the full cipher
            (``R - 1`` for a freshly constructed cipher, or the last
            round of the ``R`` supplied in slicing mode).  This
            allows constructing a slice ``round_start..round_end``
            without unwanted extra key additions.


            Round subcipher node indices are stored in
            ``cipher.round_outputs`` (in order) so that external tools
            can slice the cipher graph between any two round
            boundaries. Each entry is the main-cipher node index of
            the corresponding round subcipher, so a slice from round
            ``a`` to ``b`` can be assembled by deep-copying
            ``cipher.nodes[cipher.round_outputs[i]]`` for
            ``i = a .. b`` and rewiring them into a new
            ``SBoxCipher``.

        TESTS::

            sage: from civerly.cipher_implementations.aradi import ARADI_CVL
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
            sage: aradi = ARADI_CVL(rks=rks)
            sage: hex(vec_to_int(aradi(int_to_vec(0x0, 128))))
            '0x3f09abf400e3bd7403260defb7c53912'

            sage: # Constructing the same cipher from the master key
            sage: key = [
            ....:   0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C,
            ....:   0x13121110, 0x17161514, 0x1B1A1918, 0x1F1E1D1C,
            ....: ]
            sage: aradi_from_key = ARADI_CVL(key=key)
            sage: hex(vec_to_int(aradi_from_key(int_to_vec(0x0, 128))))
            '0x3f09abf400e3bd7403260defb7c53912'

        Analyse ARADI with MILP (matching https://eprint.iacr.org/2024/1324.pdf)::

            sage: # optional - scip # doctest: +ELLIPSIS
            ....: from civerly.cipher_implementations.aradi import ARADI_CVL
            ....: from civerly.model_options import *
            ....: aradi_small = ARADI_CVL(R=2, rks=[0x0]*3)
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
        rks_provided = rks is not None
        if rks is None:
            rks = []

        if name is None:
            name = "ARADI"

        if round_start != 0 or round_end is not None:
            if round_end is None:
                raise ValueError(
                    "round_end must be specified when round_start is not 0."
                )
            actual_rounds = round_end - round_start + 1
            if actual_rounds <= 0:
                raise ValueError(
                    f"Invalid round range: round_start={round_start}, round_end={round_end}"
                )
            # When slicing, ``R`` denotes the number of rounds of the
            # underlying full cipher.  If it is omitted, default to the
            # standard 16 rounds.
            full_rounds = R if R is not None else 16
            if full_rounds <= round_end:
                raise ValueError("R must be a positive integer greater than round_end.")
        else:
            if R is None:
                R = 16
            actual_rounds = R
            round_end = round_start + R - 1
            full_rounds = R

        # ARADI uses one 128-bit key per round.  A post-whitening key is
        # appended only when the requested slice ends at the cipher's final
        # round (``round_end == full_rounds - 1``).  When ``round_start`` is
        # not ``0`` no pre-whitening is performed; the first round of the
        # slice is simply keyed with ``rks[0]``.
        include_post_whiten = round_end + 1 == full_rounds
        expected_rks_count = actual_rounds + (1 if include_post_whiten else 0)

        # NOTE: this implements the application of the key schedule?
        if key is not None:
            if rks_provided:
                raise ValueError(
                    "ARADI_CVL accepts either explicit round keys via `rks` "
                    "or a master key via `key`, not both."
                )
            if full_rounds > 16:
                raise ValueError("When `key` is provided, `R` must not exceed 16.")
            full_rks = _aradi_key_schedule(key)
            needed = expected_rks_count
            if round_start + needed > len(full_rks):
                raise ValueError(
                    "Insufficient round keys derived from the master key "
                    f"for the requested slice ({round_start}..{round_end})."
                )
            rks = full_rks[round_start : round_start + needed]

        if len(rks) != expected_rks_count:
            raise ValueError(
                f"ARADI requires exactly {expected_rks_count} round keys "
                f"for rounds {round_start}..{round_end}, got {len(rks)}"
            )

        cipher = SBoxCipher(128, 128, name=name)

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

        node = cipher.IN
        round_outputs = []

        # Post-whitening is appended after the last round only when the slice
        # ends at the cipher's final round.
        include_post_whiten = round_end + 1 == full_rounds

        for round_index in range(round_start, round_end + 1):
            round_cipher = SBoxCipher(128, 128, name=f"ARADI-round-{round_index}")
            rk = RoundkeyXOR_CVL(128, rks[round_index - round_start], name="RK")
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

            round_node = cipher.add_subcipher(
                round_cipher,
                [
                    (
                        cipher.IN if round_index == round_start else node,
                        (bit_index, bit_index),
                    )
                    for bit_index in range(128)
                ],
            )
            round_outputs.append(round_node)
            node = round_node

        if include_post_whiten:
            post_rk = RoundkeyXOR_CVL(128, rks[actual_rounds], name="PostRK")
            node = cipher.add_subcipher(
                post_rk, [(node, (bit_index, bit_index)) for bit_index in range(128)]
            )

        cipher.add_output([(node, (bit_index, bit_index)) for bit_index in range(128)])

        self.cipher = cipher
        cipher.round_outputs = round_outputs

    def __new__(cls, *args, **kwargs):
        """Return the constructed cipher graph instance."""
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
