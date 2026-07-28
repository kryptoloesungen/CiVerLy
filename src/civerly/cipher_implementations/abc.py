from sage.crypto.sbox import SBox

from civerly.component import (
    XOR_CVL,
    PermuteLayer_CVL,
    RotateLayer_CVL,
    RoundkeyXOR_CVL,
    SBox_CVL,
)
from civerly.sboxcipher import SBoxCipher


class ABC_CVL:
    def __init__(self, R=16, rks=[], name=None):
        r"""
        The ABC cipher, a 128 bit block size Feistel cipher patented by Apple
        and first analysed in
        https://link.springer.com/chapter/10.1007/978-3-031-56232-7_13.
        The main weakness is the lack of diffusion between each byte of
        the state, which CiVerLy also recognizes.


        TESTS:

            sage: from civerly.cipher_implementations.abc import ABC_CVL
            sage: from civerly.util import vec_to_int, int_to_vec
            sage: # rks from master key = 0
            sage: rks = [
            ....:   0x0,
            ....:   0xffffffffffffffff, 0x9999999999999999, 0xffffffffffffffff,
            ....:   0x6666666666666666, 0xffffffffffffffff, 0xffffffffffffffff,
            ....:   0x3434343434343434
            ....: ]
            sage: abc = ABC_CVL(R=1, rks=rks)
            sage: hex(vec_to_int(abc(int_to_vec(0x0, 128))))
            '0x6733ce016733ce01'
            sage: hex(vec_to_int(abc(int_to_vec(
            ....:   0x80512957fea0c117_80512957fea0c117,
            ....: 128))))
            '0x80512957fea0c1179a06f273f61a9cb1'

            sage: abc = ABC_CVL(R=8, rks=rks)
            sage: arr = [(
            ....:   0xeb9b8dbebfc68d8c9c7e91ce2836fa7f,
            ....:   0x54b692ebe6e8198d215a24b81f291e82
            ....: ),(
            ....:   0x2d4c5b0e5eeedd821916bd8e72a1700a,
            ....:   0x4f961777cbf7c999cd2c0e968898cfa7
            ....: ),(
            ....:   0x94fb6544944026084bc1863299f6b5a7,
            ....:   0x3ddc9fb1b85128b1d8739c457dfc2e8c
            ....: ),(
            ....:   0xa3d1c9bfff89ec12348de63c799a6d4b,
            ....:   0xa6d93553cb5ceb964496e01aeb8285ad
            ....: ),(
            ....:   0xd4b8d6830845d1dd11aa295c1822187a,
            ....:   0x5ee50d19680f3ef8a5cde582f1700f55
            ....: ),(
            ....:   0xdaad70c40432094541a0892d710a474d,
            ....:   0xcaca2295f6aa549e3fc08c0a64e873fc
            ....: ),(
            ....:   0x3ab3fa6acbcc664b438a265131480213,
            ....:   0x9322842a3c68b79b81fc2ef630a81129
            ....: ),(
            ....:   0xd41a26492da021e844220bdccf52a0f3,
            ....:   0xb70b7c9fda7c96d5ecec7e0a1cf1ef18
            ....: ),(
            ....:   0x82aefbfdcf17b9816222007866ea44be,
            ....:   0xa91976b572a75b1bd431a54673853370
            ....: ),(
            ....:   0x754c050715068a4e8c3adacc68c4082b,
            ....:   0x17f399477de8c1b8f6f9f87a2dc07515
            ....: ),(
            ....:   0xee311ba621201f47e5dd25260d585cbc,
            ....:   0x15f418df71033acc7604d77fc70eccb9
            ....: )]
            sage: all([
            ....:   vec_to_int(abc(int_to_vec(P, 128))) == C for P, C in arr
            ....: ])
            True

        Model ABC in CiVerLy::

            sage: from civerly.cipher_implementations.abc import ABC_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   abc_cipher = ABC_CVL(4)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     solve_range=(0, 10),
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir)
            ....:   )
            ....:   abc_cipher.analyse(model_options)
            12640 variables and 44257 clauses were written to '...'
            3

        """
        if rks == []:
            rks = [0x0 for _ in range(R)]

        if name is None:
            name = "ABC"

        cipher = SBoxCipher(128, 128, name=name)
        abc_round = SBoxCipher(128, 128, name="ABC-round")

        rk = RoundkeyXOR_CVL(64, const=0x0, name="rk")
        xor = XOR_CVL(64, name="xor")

        bigR = PermuteLayer_CVL([6, 5, 2, 7, 4, 1, 0, 3], word_coarseness=8, name="R")
        smallR = SBoxCipher(64, 64, name="r")

        for j in range(8):
            node = smallR.add_subcipher(
                RotateLayer_CVL(8, j, name=f"r{j}"),
                [(smallR.IN, (i + 8 * j, i)) for i in range(8)],
            )
            smallR.add_output([(node, (i, i + 8 * j)) for i in range(8)])

        sb = SBox_CVL(
            SBox(
                [
                    0x4,
                    0xC,
                    0x0,
                    0x8,
                    0x6,
                    0xE,
                    0x1,
                    0xB,
                    0x9,
                    0xD,
                    0x2,
                    0x5,
                    0xA,
                    0xF,
                    0x3,
                    0x7,
                ]
            ),
            name="S",
        )
        sb_layer = SBoxCipher(64, 64, name="S-Layer")
        for j in range(16):
            node = sb_layer.add_subcipher(
                sb, [(sb_layer.IN, (i + 4 * j, i)) for i in range(4)]
            )
            sb_layer.add_output([(node, (i, i + 4 * j)) for i in range(4)])

        bs = SBox_CVL(
            SBox(
                [
                    0x9B,
                    0x9E,
                    0xA1,
                    0xA4,
                    0xA7,
                    0xAA,
                    0xAD,
                    0xB0,
                    0xB3,
                    0xB6,
                    0xB9,
                    0xBC,
                    0xBF,
                    0xC2,
                    0xC5,
                    0xC8,
                    0xCB,
                    0xCE,
                    0xD1,
                    0xD4,
                    0xD7,
                    0xDA,
                    0xDD,
                    0xE0,
                    0xE3,
                    0xE6,
                    0xE9,
                    0xEC,
                    0xEF,
                    0xF2,
                    0xF5,
                    0xF8,
                    0xFB,
                    0xFE,
                    0x01,
                    0x04,
                    0x07,
                    0x0A,
                    0x0D,
                    0x10,
                    0x13,
                    0x16,
                    0x19,
                    0x1C,
                    0x1F,
                    0x22,
                    0x25,
                    0x28,
                    0x2B,
                    0x2E,
                    0x31,
                    0x34,
                    0x37,
                    0x3A,
                    0x3D,
                    0x40,
                    0x43,
                    0x46,
                    0x49,
                    0x4C,
                    0x4F,
                    0x52,
                    0x55,
                    0x58,
                    0x5B,
                    0x5E,
                    0x61,
                    0x64,
                    0x67,
                    0x6A,
                    0x6D,
                    0x70,
                    0x73,
                    0x76,
                    0x79,
                    0x7C,
                    0x7F,
                    0x82,
                    0x85,
                    0x88,
                    0x8B,
                    0x8E,
                    0x91,
                    0x94,
                    0x97,
                    0x9A,
                    0x9D,
                    0xA0,
                    0xA3,
                    0xA6,
                    0xA9,
                    0xAC,
                    0xAF,
                    0xB2,
                    0xB5,
                    0xB8,
                    0xBB,
                    0xBE,
                    0xC1,
                    0xC4,
                    0xC7,
                    0xCA,
                    0xCD,
                    0xD0,
                    0xD3,
                    0xD6,
                    0xD9,
                    0xDC,
                    0xDF,
                    0xE2,
                    0xE5,
                    0xE8,
                    0xEB,
                    0xEE,
                    0xF1,
                    0xF4,
                    0xF7,
                    0xFA,
                    0xFD,
                    0x00,
                    0x03,
                    0x06,
                    0x09,
                    0x0C,
                    0x0F,
                    0x12,
                    0x15,
                    0x18,
                    0x1B,
                    0x1E,
                    0x21,
                    0x24,
                    0x27,
                    0x2A,
                    0x2D,
                    0x30,
                    0x33,
                    0x36,
                    0x39,
                    0x3C,
                    0x3F,
                    0x42,
                    0x45,
                    0x48,
                    0x4B,
                    0x4E,
                    0x51,
                    0x54,
                    0x57,
                    0x5A,
                    0x5D,
                    0x60,
                    0x63,
                    0x66,
                    0x69,
                    0x6C,
                    0x6F,
                    0x72,
                    0x75,
                    0x78,
                    0x7B,
                    0x7E,
                    0x81,
                    0x84,
                    0x87,
                    0x8A,
                    0x8D,
                    0x90,
                    0x93,
                    0x96,
                    0x99,
                    0x9C,
                    0x9F,
                    0xA2,
                    0xA5,
                    0xA8,
                    0xAB,
                    0xAE,
                    0xB1,
                    0xB4,
                    0xB7,
                    0xBA,
                    0xBD,
                    0xC0,
                    0xC3,
                    0xC6,
                    0xC9,
                    0xCC,
                    0xCF,
                    0xD2,
                    0xD5,
                    0xD8,
                    0xDB,
                    0xDE,
                    0xE1,
                    0xE4,
                    0xE7,
                    0xEA,
                    0xED,
                    0xF0,
                    0xF3,
                    0xF6,
                    0xF9,
                    0xFC,
                    0xFF,
                    0x02,
                    0x05,
                    0x08,
                    0x0B,
                    0x0E,
                    0x11,
                    0x14,
                    0x17,
                    0x1A,
                    0x1D,
                    0x20,
                    0x23,
                    0x26,
                    0x29,
                    0x2C,
                    0x2F,
                    0x32,
                    0x35,
                    0x38,
                    0x3B,
                    0x3E,
                    0x41,
                    0x44,
                    0x47,
                    0x4A,
                    0x4D,
                    0x50,
                    0x53,
                    0x56,
                    0x59,
                    0x5C,
                    0x5F,
                    0x62,
                    0x65,
                    0x68,
                    0x6B,
                    0x6E,
                    0x71,
                    0x74,
                    0x77,
                    0x7A,
                    0x7D,
                    0x80,
                    0x83,
                    0x86,
                    0x89,
                    0x8C,
                    0x8F,
                    0x92,
                    0x95,
                    0x98,
                ],
                name="BS",
            )
        )

        bs_layer = SBoxCipher(64, 64, name="BS-Layer")
        for j in range(8):
            node = bs_layer.add_subcipher(
                bs, [(bs_layer.IN, (i + 8 * j, i)) for i in range(8)]
            )
            bs_layer.add_output([(node, (i, i + 8 * j)) for i in range(8)])

        node_rk = abc_round.add_subcipher(
            rk, [(abc_round.IN, (i + 64, i)) for i in range(64)]
        )
        node_s = abc_round.add_subcipher(
            sb_layer, [(node_rk, (i, i)) for i in range(64)]
        )
        node_r = abc_round.add_subcipher(smallR, [(node_s, (i, i)) for i in range(64)])
        node_bigr = abc_round.add_subcipher(
            bigR, [(abc_round.IN, (i, i)) for i in range(64)]
        )
        node_xor = abc_round.add_subcipher(
            xor,
            [(node_r, (i, i)) for i in range(64)]
            + [(node_bigr, (i, i + 64)) for i in range(64)],
        )
        node_bs = abc_round.add_subcipher(
            bs_layer, [(node_xor, (i, i)) for i in range(64)]
        )

        abc_round.add_output([(node_bs, (i, i + 64)) for i in range(64)])
        abc_round.add_output([(abc_round.IN, (i + 64, i)) for i in range(64)])

        node = cipher.IN
        for r in range(R):
            abc_round.nodes[node_rk].const = rks[r]
            node = cipher.add_subcipher(abc_round, [(node, (i, i)) for i in range(128)])
        cipher.add_output([(node, (i, i)) for i in range(128)])

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
