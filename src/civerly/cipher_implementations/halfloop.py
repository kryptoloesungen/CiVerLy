r"""
Implementation of HALFLOOP-24.
"""

from sage.crypto.sboxes import AES as AES_S
from sage.matrix.special import block_matrix
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.rings.polynomial.polynomial_ring_constructor import PolynomialRing

from civerly.aeslike import AESlike
from civerly.component import (
    C_CVL,
    XOR_CVL,
    ConstXOR_CVL,
    LinearLayer_CVL,
    PermuteLayer_CVL,
    SBox_CVL,
)
from civerly.sboxcipher import SBoxCipher


class HALFLOOP_CVL:
    def __init__(self, R, k=None, name="HALFLOOP-24") -> None:
        r"""
        Implementation of HALFLOOP-24 in CiVerLy, together with its key schedule.

        INPUT:

            - ``R`` -- integer; Number of rounds (must be <= 10)

            - ``k`` -- integer (128-bit); Master key (default: None).  When given,
              the round keys are derived and injected immediately.

            - ``name`` -- string; The name of the cipher (default: "HALFLOOP-24").
              This will be used to name the cipher and the corresponding file
              generated (such as the reports and cipher graphs).

        TESTS::

        The test vectors come from the original paper 'Breaking HALFLOOP-24'
        or from a reference implementation. Testing MixColumns in isolation:

            sage: from civerly.cipher_implementations.halfloop import HALFLOOP_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: mc = HALFLOOP_CVL(1).nodes[5].nodes[3]
            sage: all([
            ....:   vec_to_int(mc(int_to_vec(0x1, 24))) == 0x020109,
            ....:   vec_to_int(mc(int_to_vec(0x100, 24))) == 0x010902,
            ....:   vec_to_int(mc(int_to_vec(0x10000, 24))) == 0x090201,
            ....:   vec_to_int(mc(int_to_vec(0xf328b8, 24))) == 0x6936ac
            ....: ])
            True

        Testing output of key schedule:

            sage: from civerly.cipher_implementations.halfloop import HALFLOOP_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: ks = HALFLOOP_CVL(1).nodes[3]
            sage: hex(vec_to_int(ks(int_to_vec(
            ....:   0x2b7e151628aed2a6abf7158809cf4f3c
            ....:   ^^ (0x543bd88000017550 << 64), 128))))
            '0x7f45cd9628afa7f6abf7158809cf4f3cf4c12697dc6e8161779994e97e56dbd547'
            sage: from civerly.cipher_implementations.halfloop import HALFLOOP_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: ks = HALFLOOP_CVL(1).nodes[3]
            sage: hex(vec_to_int(ks(int_to_vec(
            ....:   0x1628aed2a6abf7158809cf4f3c << 8
            ....:   ^^ (0x8000017550 << (64+8)), 128))))
            '0x9628afa7f6abf7158809cf4f3c0085ebf5a22a4c0309dd598b001216b700c0'

        Testing 1 round of HALFLOOP with the test vector from
        'Breaking HALFLOOP-24':

            sage: masterkey = 0x7f45cd9628afa7f6abf7158809cf4f3c
            sage: from civerly.cipher_implementations.halfloop import \
            ....:   HALFLOOP_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: vec_to_int(HALFLOOP_CVL(1, k=masterkey)(
            ....:   int_to_vec((0x010203 << 64), 88))
            ....: ) == 0xff1e03
            True
            sage: from civerly.cipher_implementations.halfloop import \
            ....:   HALFLOOP_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: vec_to_int(HALFLOOP_CVL(2, k=masterkey)(
            ....:   int_to_vec((0x010203 << 64), 88))
            ....: ) == 0xe87de6
            True

        Testing full HALFLOOP:

            sage: from civerly.cipher_implementations.halfloop import \
            ....:   HALFLOOP_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: test_vecs = [
            ....:   0x010203, 0x7e47ce, 0xff1e03, 0xe87de6, 0xec961f, 0xd15ba5,
            ....:   0x67e02e, 0xb90022, 0x145676, 0x6dd441, 0x4cbcad, 0xf28c1e
            ....: ]
            sage: masterkey = 0x2b7e151628aed2a6abf7158809cf4f3c
            sage: tweak = 0x543bd88000017550
            sage: all([
            ....:   vec_to_int(HALFLOOP_CVL(R, k=masterkey)(int_to_vec(
            ....:     (0x010203 << 64) | tweak, 24 + 64))
            ....:   ) == test_vecs[R+1]
            ....:   for R in range(1, 10)
            ....: ])
            True

        """
        RCs = [0x01, 0x02]  # AES key schedule is only applied for 2 rounds

        assert R <= 10

        if k is None:
            k = 0x0

        sboxlayer = AESlike(8, 3, 1, name="SBoxLayer")
        sb = SBox_CVL(AES_S, name="SBox")

        for i in range(3):
            node = sboxlayer.add_subcipher(sb, [(sboxlayer.IN, (i, 0))])
            sboxlayer.add_output([(node, (0, i))])

        p = [0, 1, 2, 3, 4, 5, 6, 7,
             10, 11, 12, 13, 14, 15, 8, 9,
             20, 21, 22, 23, 16, 17, 18, 19]  # fmt: skip
        RotateRows = PermuteLayer_CVL(p, name="RotateRows")

        AES_irr = PolynomialRing(GF(2), name="a")("a^8 + a^4 + a^3 + a + 1")
        F = GF(2**8, names="z", modulus=AES_irr, repr="int")

        I = F.from_integer(1).matrix()  # noqa: E741
        II = F.from_integer(2).matrix()
        IX = F.from_integer(9).matrix()
        # SageMath's "from_integer" has a different endianness than we need.
        # We flip the matrix accordingly:
        I = I.transpose()  # noqa: E741
        II = II.transpose()
        IX = IX.transpose()
        I.reverse_rows_and_columns()
        II.reverse_rows_and_columns()
        IX.reverse_rows_and_columns()
        I = I.transpose()  # noqa: E741
        II = II.transpose()
        IX = IX.transpose()

        M = block_matrix(
            GF(2), [[IX, I, II], [II, IX, I], [I, II, IX]], subdivide=False
        )

        MC = LinearLayer_CVL(
            M, branch_number_differential=5, branch_number_linear=5, name="MixColumn"
        )

        halfloop_round = SBoxCipher(48, 24, "Round")
        XOR = XOR_CVL(24, name="KeyAdd")
        edges = [(halfloop_round.IN, (i, i)) for i in range(24)]
        node_sboxlayer = halfloop_round.add_subcipher(sboxlayer, edges)
        edges = [(node_sboxlayer, (i, i)) for i in range(24)]
        node_rotaterows = halfloop_round.add_subcipher(RotateRows, edges)
        edges = [(node_rotaterows, (i, i)) for i in range(24)]
        node_mc = halfloop_round.add_subcipher(MC, edges)
        edges = [(node_mc, (i, i)) for i in range(24)]
        edges += [(halfloop_round.IN, (i + 24, i + 24)) for i in range(24)]
        node_xor = halfloop_round.add_subcipher(XOR, edges)
        edges = [(node_xor, (i, i)) for i in range(24)]
        halfloop_round.add_output(edges)

        key_schedule = SBoxCipher(128, 264, "Key Schedule")
        G = AESlike(8, 4, 1, "G")
        for i in range(4):
            node = G.add_subcipher(sb, [(G.IN, (i, 0))])
            if i == 1:
                node = G.add_subcipher(
                    ConstXOR_CVL(8, RCs[0], name="RC"), [(node, (0, 0))]
                )
            G.add_output([(node, (0, (i - 1) % 4))])

        XOR32 = XOR_CVL(32, name="XOR-32")
        XOR8 = XOR_CVL(8, name="XOR-8")
        rc2 = ConstXOR_CVL(8, RCs[1])

        edges = [(key_schedule.IN, (i + 96, i)) for i in range(32)]
        node_g = key_schedule.add_subcipher(G, edges)
        edges = [(key_schedule.IN, (i, i)) for i in range(32)]
        edges += [(node_g, (i, i + 32)) for i in range(32)]
        node_XOR1 = key_schedule.add_subcipher(XOR32, edges)
        edges = [(key_schedule.IN, (32 + i, i)) for i in range(32)]
        edges += [(node_XOR1, (i, i + 32)) for i in range(32)]
        node_XOR2 = key_schedule.add_subcipher(XOR32, edges)
        edges = [(key_schedule.IN, (64 + i, i)) for i in range(32)]
        edges += [(node_XOR2, (i, i + 32)) for i in range(32)]
        node_XOR3 = key_schedule.add_subcipher(XOR32, edges)
        edges = [(key_schedule.IN, (96 + i, i)) for i in range(32)]
        edges += [(node_XOR3, (i, i + 32)) for i in range(32)]
        node_XOR4 = key_schedule.add_subcipher(XOR32, edges)
        edges = [(node_XOR4, (8 + i, i)) for i in range(8)]
        node_S = key_schedule.add_subcipher(sb, edges)
        edges = [(node_S, (i, i)) for i in range(8)]
        node_rc2 = key_schedule.add_subcipher(rc2, edges)
        edges = [(node_rc2, (i, i)) for i in range(8)]
        edges += [(node_XOR1, (i, i + 8)) for i in range(8)]
        node_XOR5 = key_schedule.add_subcipher(XOR8, edges)

        edges = [(key_schedule.IN, (i, i)) for i in range(128)]
        edges += [(node_XOR1, (i, 128 + i)) for i in range(32)]
        edges += [(node_XOR2, (i, 160 + i)) for i in range(32)]
        edges += [(node_XOR3, (i, 192 + i)) for i in range(32)]
        edges += [(node_XOR4, (i, 224 + i)) for i in range(32)]
        edges += [(node_XOR5, (i, 256 + i)) for i in range(8)]
        key_schedule.add_output(edges)

        halfloop_cipher = SBoxCipher(24 + 64, 24, name=name)
        K = C_CVL(64, k % (1 << 64), "k2")  # k2, second half of key
        K = halfloop_cipher.add_subcipher(K, [])

        # add k1 to tweak
        node_addkey1 = ConstXOR_CVL(64, const=((k >> 64) % (1 << 64)), name="t+k1")
        edges = [(halfloop_cipher.IN, (i + 24, i)) for i in range(64)]
        node_afteraddkey1 = halfloop_cipher.add_subcipher(node_addkey1, edges)
        # send (k1 + t) || k2 into key schedule
        edges = [(node_afteraddkey1, (i, i)) for i in range(64)]
        edges += [(K, (i, i + 64)) for i in range(64)]
        node_ks = halfloop_cipher.add_subcipher(key_schedule, edges)

        # initial key add
        edges = [(halfloop_cipher.IN, (i, i)) for i in range(24)]
        edges += [(node_ks, (i, i + 24)) for i in range(24)]
        node_XOR = halfloop_cipher.add_subcipher(XOR, edges)
        for r in range(R):
            edges = [(node_XOR, (i, i)) for i in range(24)]
            edges += [(node_ks, (i + (r + 1) * 24, i + 24)) for i in range(24)]
            node_XOR = halfloop_cipher.add_subcipher(halfloop_round, edges)

        edges = [(node_XOR, (i, i)) for i in range(24)]
        halfloop_cipher.add_output(edges)

        self.halfloop_cipher = halfloop_cipher

    def __new__(cls, *args, **kwargs):
        """Instantiate HALFLOOP."""
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.halfloop_cipher
