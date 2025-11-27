r"""
Implementation of HALFLOOP-24.
"""

from civerly.aeslike import AESlike
from civerly.sboxcipher import SBoxCipher
from civerly.component import SBox_CVL, PermuteLayer_CVL, LinearLayer_CVL
from civerly.component import C_CVL, XOR_CVL

from sage.rings.finite_rings.finite_field_constructor import GF
from sage.rings.polynomial.polynomial_ring_constructor import PolynomialRing
from sage.matrix.special import block_matrix
from sage.crypto.sboxes import AES as AES_S


class HALFLOOP_CVL:
    """
    Implementation of HALFLOOP-24 in CiVerLy.

    .. WARNING::

       Notice that while the implementation already allows to model HALFLOOP
       and finds the probability-one differential over six rounds, it is not
       complete. That is, the values of some constants are missing and hence
       the evaluating this implementation will return wrong results.
    """

    def __init__(self, R, name=None) -> None:
        r"""
        Implement HALFLOOP in CiVerLy.

        INPUT:

            - ``R`` -- integer; Number of rounds.

            - ``name`` -- string; The name of the cipher (optional).
              This will be used to name the cipher and the corresponding file
              generated (such as the reports and cipher graphs).
        """
        assert R <= 10

        if name is None:
            name = "HALFLOOP-24"

        sboxlayer = AESlike(8, 3, 1, name="SBoxLayer")
        sb = SBox_CVL(AES_S, name="SBox")

        for i in range(3):
            node = sboxlayer.add_subcipher(sb, [(sboxlayer.IN, (i, 0))])
            sboxlayer.add_output([(node, (0, i))])

        p = [0, 1, 2, 3, 4, 5, 6, 7,
             14, 15, 8, 9, 10, 11, 12, 13,
             20, 21, 22, 23, 16, 17, 18, 19]
        RotateRows = PermuteLayer_CVL(p, name="RotateRows")

        AES_irr = PolynomialRing(GF(2), name="a")("a^8 + a^4 + a^3 + a + 1")
        F = GF(2**8, names='z', modulus=AES_irr, repr="int")

        I = F.from_integer(1).matrix()  # noqa: E741
        II = F.from_integer(2).matrix()
        IX = F.from_integer(9).matrix()

        M = block_matrix(
            GF(2),
            [[I, II, IX], [II, IX, I], [IX, I, II]],
            subdivide=False
        )

        MC = LinearLayer_CVL(M, branch_number_differential=5,
                             branch_number_linear=5, name="MixColumn")

        halfloop_round = SBoxCipher(48, 24, "Round")
        XOR = XOR_CVL(24, name="KeyAdd")
        edges = [(halfloop_round.IN, (i, i)) for i in range(24)]
        node_sboxlayer = halfloop_round.add_subcipher(sboxlayer, edges)
        edges = [(node_sboxlayer, (i, i)) for i in range(24)]
        node_rotaterows = halfloop_round.add_subcipher(RotateRows, edges)
        edges = [(node_rotaterows, (i, i)) for i in range(24)]
        node_mc = halfloop_round.add_subcipher(MC, edges)
        edges = [(node_mc, (i, i)) for i in range(24)]
        edges += [(halfloop_round.IN, (i+24, i+24)) for i in range(24)]
        node_xor = halfloop_round.add_subcipher(XOR, edges)
        edges = [(node_xor, (i, i)) for i in range(24)]
        halfloop_round.add_output(edges)

        key_schedule = SBoxCipher(128, 264, "Key Schedule")
        G = AESlike(8, 4, 1, "G")
        # TODO: round constant
        for i in range(4):
            node = G.add_subcipher(sb, [(G.IN, (i, 0))])
            G.add_output([(node, (0, (i-1) % 4))])

        XOR32 = XOR_CVL(32, name="XOR-32")
        XOR8 = XOR_CVL(8, name="XOR-8")

        edges = [(key_schedule.IN, (i+96, i)) for i in range(32)]
        node_g = key_schedule.add_subcipher(G, edges)
        edges = [(key_schedule.IN, (i, i)) for i in range(32)]
        edges += [(node_g, (i, i+32)) for i in range(32)]
        node_XOR1 = key_schedule.add_subcipher(XOR32, edges)
        edges = [(key_schedule.IN, (32+i, i)) for i in range(32)]
        edges += [(node_XOR1, (i, i+32)) for i in range(32)]
        node_XOR2 = key_schedule.add_subcipher(XOR32, edges)
        edges = [(key_schedule.IN, (64+i, i)) for i in range(32)]
        edges += [(node_XOR2, (i, i+32)) for i in range(32)]
        node_XOR3 = key_schedule.add_subcipher(XOR32, edges)
        edges = [(key_schedule.IN, (96+i, i)) for i in range(32)]
        edges += [(node_XOR3, (i, i+32)) for i in range(32)]
        node_XOR4 = key_schedule.add_subcipher(XOR32, edges)
        edges = [(node_XOR4, (8+i, i)) for i in range(8)]
        node_S = key_schedule.add_subcipher(sb, edges)
        edges = [(node_S, (i, i)) for i in range(8)]
        edges += [(node_XOR1, (i, i+8)) for i in range(8)]
        node_XOR5 = key_schedule.add_subcipher(XOR8, edges)
        # TODO: round constant

        edges = [(key_schedule.IN, (i, i)) for i in range(128)]
        edges += [(node_XOR1, (i, 128+i)) for i in range(32)]
        edges += [(node_XOR2, (i, 160+i)) for i in range(32)]
        edges += [(node_XOR3, (i, 192+i)) for i in range(32)]
        edges += [(node_XOR4, (i, 224+i)) for i in range(32)]
        edges += [(node_XOR5, (i, 256+i)) for i in range(8)]
        key_schedule.add_output(edges)

        halfloop_cipher = SBoxCipher(24+64, 24, "HALFLOOP-24")
        K = C_CVL(64, 0)  # uncontrollable part of key
        K = halfloop_cipher.add_subcipher(K, [])
        edges = [(halfloop_cipher.IN, (i+24, i)) for i in range(64)]
        edges += [(K, (i, i+64)) for i in range(64)]
        node_ks = halfloop_cipher.add_subcipher(key_schedule, edges)
        edges = [(halfloop_cipher.IN, (i, i)) for i in range(24)]
        edges += [(node_ks, (i, i+24)) for i in range(24)]
        node_XOR = halfloop_cipher.add_subcipher(XOR, edges)
        for r in range(R):
            edges = [(node_XOR, (i, i)) for i in range(24)]
            edges += [(node_ks, (i+(r+1)*24, i+24)) for i in range(24)]
            node_XOR = halfloop_cipher.add_subcipher(halfloop_round, edges)
            # TODO: no MC in round 10
        halfloop_cipher.add_output([(node_XOR, (i, i)) for i in range(24)])
        self.halfloop_cipher = halfloop_cipher

    def __new__(cls, *args, **kwargs):
        """Instantiate HALFLOOP."""
        instance = super(HALFLOOP_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.halfloop_cipher
