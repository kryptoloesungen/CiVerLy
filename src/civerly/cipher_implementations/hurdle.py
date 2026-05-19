from sage.crypto.sbox import SBox
from civerly.wordbasedcipher import WordBasedCipher
from civerly.component import ModAdd_CVL, RK_CVL, XOR_CVL, SBox_CVL
from civerly.component import PermuteLayer_CVL


def hurdle_key_schedule(masterkey):
    r"""
    The HURDLE key schedule, as implemented in `HURDLE_set_key` in
    MidnightBlue's implementation.

    TESTS::
        sage: from civerly.cipher_implementations.hurdle \
        ....:   import hurdle_key_schedule
        sage: for rk in [f'{rk:024x}' for rk in hurdle_key_schedule(
        ....:   0xabcdef12c001f00ddeadbeefcafebabe
        ....: )]: print(rk)
        c001f00ddeadbeefcafebabe
        d4e9300ac6b08db53e63e637
        c9da6afe5bec0423a46d0f23
        9553fc64550510cb646a173e
        7c4714a4521d0df83e9e8a62
        dd05c2cdc034ad9491e3af7f
        edc63c6f4746e8b5c251f135
        3fbf6a0269fb06ef94547c1a
        825130546c7629e4680f96c8
        0f7e3ba8379cfb9d3e62b875
        e5ac42fe5ab246736434bdf8
        0a33eb7dc048af5ae16958b5
        0497976f62eb5a46464e09a9
        920d998676039a415e533af3
        7acd9e9e6b30c0b5c30fb365
        49976a0337b9562fcde6a78d
        sage: for rk in [f'{rk:024x}' for rk in hurdle_key_schedule(
        ....:   0x99990099991188992277993366994455
        ....: )]: print(rk)
        991188992277993366994455
        0eceeca6a14e66876a8c6d6e
        373158aab4675d33dcf9f3f9
        1e0aec1cc1f9caecb8c670c0
        809d3378fe7af3130cca65e9
        01a9a5332b06f97b1ababf07
        024d657f3fd2146fe58d5d52
        ab43b025b55761117f6628f5
        2e36cebf5e22c66f311fee5c
        5b91b0f127e46f61e44564d9
        9d38be247d6eea149adf8fac
        6dcd004f94a72403f111cc49
        36c378e43bfb22d2ba942e75
        82750d7aac2446ed39add1c1
        5d1132f995dbf2e12c84ea75
        a2a53eecbce04657591a7daa

    """
    k = [(masterkey >> (8*(15 - i))) & 0xff for i in range(16)]
    kk = [
        [k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15]],
        [k[5], k[6], k[7], k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15], k[0], k[1], k[2], k[3], k[4]],
        [k[10], k[11], k[12], k[13], k[14], k[15], k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8], k[9]],
        [k[15], k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8], k[9], k[10], k[11], k[12], k[13], k[14]],
        [k[4], k[5], k[6], k[7], k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15], k[0], k[1], k[2], k[3]],
        [k[7], k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15], k[0], k[1], k[2], k[3], k[4], k[5], k[6]],
        [k[14], k[15], k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8], k[9], k[10], k[11], k[12], k[13]],
        [k[3], k[4], k[5], k[6], k[7], k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15], k[0], k[1], k[2]],
        [k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15], k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7]],
        [k[13], k[14], k[15], k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8], k[9], k[10], k[11], k[12]],
        [k[2], k[3], k[4], k[5], k[6], k[7], k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15], k[0], k[1]],
        [k[9], k[10], k[11], k[12], k[13], k[14], k[15], k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8]],
        [k[12], k[13], k[14], k[15], k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8], k[9], k[10], k[11]],
        [k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15], k[0]],
        [k[6], k[7], k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15], k[0], k[1], k[2], k[3], k[4], k[5]],
        [k[11], k[12], k[13], k[14], k[15], k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8], k[9], k[10]]
    ]
    const = [
        [0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00],   # rk00
        [0x3C,  0xA7,  0xEC,  0x25,  0x79,  0x57,  0xDF,  0xC0,  0x38,  0x0A,  0x33,  0x1E,  0xF3,  0x8C,  0xF4,  0xF7],   # rk01
        [0x6B,  0x78,  0x2C,  0x1D,  0x73,  0x64,  0xC1,  0x33,  0xB4,  0xFE,  0xC4,  0x22,  0x54,  0x60,  0xD1,  0x8E],   # rk02
        [0x58,  0x66,  0xDF,  0x91,  0x87,  0x93,  0xFD,  0x94,  0x58,  0xDB,  0xBD,  0x75,  0x8B,  0xA0,  0xE9,  0x84],   # rk03
        [0xAF,  0x5A,  0x78,  0x7D,  0xA2,  0xEA,  0xAA,  0x4B,  0x98,  0xE3,  0xB7,  0x46,  0x95,  0x53,  0x65,  0x70],   # rk04
        [0x41,  0x05,  0x06,  0x8F,  0x32,  0xCF,  0x3C,  0x77,  0x7E,  0x9F,  0x60,  0x7B,  0x83,  0x23,  0xAE,  0x8F],   # rk05
        [0x4B,  0xD9,  0x73,  0x45,  0x02,  0xD4,  0xFC,  0x6E,  0xB7,  0x4B,  0x36,  0x18,  0x7C,  0xBE,  0x3B,  0xCB],   # rk06
        [0xE8,  0x5B,  0x82,  0x92,  0x32,  0x61,  0xC7,  0xBC,  0x86,  0x31,  0xF8,  0x55,  0x2A,  0xFF,  0xB1,  0xF5],   # rk07
        [0x5D,  0x60,  0x50,  0xA3,  0x48,  0xAF,  0x8A,  0xEA,  0xC7,  0xBB,  0xC6,  0xF6,  0xA8,  0x0E,  0x66,  0xC5],   # rk08
        [0x93,  0x2D,  0x06,  0xE2,  0xC2,  0x91,  0x29,  0x68,  0x36,  0x6C,  0xF6,  0x43,  0x93,  0xDC,  0x57,  0xBF],   # rk09
        [0xAD,  0x8E,  0x84,  0x13,  0x15,  0xA1,  0x9C,  0x53,  0xE4,  0x5D,  0x8C,  0x8D,  0xDE,  0x8A,  0x16,  0x35],   # rk10
        [0x6F,  0x43,  0xB1,  0xA9,  0xF4,  0x89,  0x55,  0xD6,  0x0D,  0xA7,  0xBD,  0x9A,  0xE0,  0x99,  0x55,  0x6B],   # rk11
        [0x95,  0x53,  0x65,  0x70,  0xAF,  0x5A,  0x78,  0x7D,  0xA2,  0xEA,  0xAA,  0x4B,  0x98,  0xE3,  0xB7,  0x46],   # rk12
        [0x66,  0xDF,  0x91,  0x87,  0x93,  0xFD,  0x94,  0x58,  0xDB,  0xBD,  0x75,  0x8B,  0xA0,  0xE9,  0x84,  0x58],   # rk13
        [0xC1,  0x33,  0xB4,  0xFE,  0xC4,  0x22,  0x54,  0x60,  0xD1,  0x8E,  0x6B,  0x78,  0x2C,  0x1D,  0x73,  0x64],   # rk14
        [0x1E,  0xF3,  0x8C,  0xF4,  0xF7,  0x3C,  0xA7,  0xEC,  0x25,  0x79,  0x57,  0xDF,  0xC0,  0x38,  0x0A,  0x33]    # rk15
    ]
    out = [sum([(kk[row][i] ^ const[row][i]) << (8*(15 - i)) for i in range(4, 16)]) for row in range(16)]

    return out


class HURDLE_F_CVL:
    def __init__(self, rk=None) -> None:
        r"""
        Implementation of HURDLE-II's F function, imitating MidnightBlue's
        implementation.

        TESTS::

            sage: from civerly.cipher_implementations.hurdle \
            ....:   import HURDLE_F_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: hurdle_f = HURDLE_F_CVL(rk=0x991188992277993366994455)
            sage: vec_to_int(hurdle_f(int_to_vec(0x2222eeee, 32))) == \
            ....:   0x2bee4c18
            True
            sage: hurdle_f = HURDLE_F_CVL(rk=0xc001f00ddeadbeefcafebabe)
            sage: vec_to_int(hurdle_f(int_to_vec(0xdeadbeef, 32))) == \
            ....:   0xAEC367D1
            True
            sage: hurdle_f = HURDLE_F_CVL(rk=0xd4e9300ac6b08db53e63e637)
            sage: vec_to_int(hurdle_f(int_to_vec(0x643DDD6F, 32))) == \
            ....:   0xDFE8AC6A
            True

        """
        if rk is None:
            rk = 0x0

        # build F function
        hurdle_f = WordBasedCipher(4, 8, 8, name="F")

        rk_comp = RK_CVL(96, rk, name="rk")
        rk_node = hurdle_f.add_subcipher(rk_comp, [])
        rk_adds = [None for _ in range(12)]

        E = [3-i for i in [1, 3, 0, 2, 3, 1, 2, 0, 3, 2, 1, 0]]
        for i in range(12):
            rk_add = ModAdd_CVL(8, name=f"rk_add{i}")
            rk_adds[i] = hurdle_f.add_subcipher(rk_add, [
                (hurdle_f.IN, (2*E[i], 0)), (hurdle_f.IN, (2*E[i] + 1, 1)),
                (rk_node, (2*i, 2)), (rk_node, (2*i + 1, 3))
            ])

        sb = SBox([
            0xF4, 0x65, 0x01, 0x00, 0xBA, 0x7A, 0xA7, 0x47, 0x98, 0xDD, 0x9D,
            0xAD, 0x96, 0x5D, 0xAA, 0x3D, 0x58, 0xC0, 0x72, 0xD8, 0x66, 0x4C,
            0x3E, 0xE0, 0x80, 0x55, 0xDE, 0x90, 0x2A, 0x4B, 0x83, 0xA0, 0x51,
            0x39, 0xED, 0x6C, 0x8A, 0x2C, 0x56, 0x60, 0x4A, 0x1F, 0xD0, 0x70,
            0x6E, 0x33, 0x8B, 0x26, 0x2E, 0x6F, 0x89, 0x48, 0x5E, 0x40, 0xC3,
            0xA4, 0xA9, 0xCF, 0x22, 0x50, 0xE1, 0x15, 0x0C, 0xAB, 0xD5, 0xF8,
            0x5F, 0x36, 0x04, 0xA6, 0x4E, 0x92, 0x1E, 0x2B, 0x88, 0x30, 0x93,
            0x45, 0x67, 0x16, 0x8C, 0x68, 0x23, 0x38, 0x61, 0x25, 0x1A, 0x81,
            0x63, 0xCB, 0xC1, 0x13, 0x41, 0x37, 0x0E, 0x97, 0x5B, 0xCA, 0x57,
            0x24, 0x4D, 0x17, 0xC4, 0xB9, 0xB3, 0xEF, 0x8D, 0x52, 0x32, 0x2F,
            0xEC, 0x20, 0xD9, 0x11, 0xD1, 0x28, 0x79, 0xDA, 0xFB, 0xE9, 0xBB,
            0x06, 0x77, 0xDB, 0xFC, 0xFE, 0xCD, 0x84, 0x1D, 0xA1, 0x54, 0x1B,
            0xB0, 0xE4, 0xCC, 0x7C, 0x2D, 0x27, 0x31, 0x49, 0xF5, 0x02, 0x69,
            0x53, 0x4F, 0x44, 0xDF, 0x18, 0x5C, 0x0F, 0xBC, 0x9B, 0x94, 0xBD,
            0xDC, 0x0B, 0xA2, 0xC7, 0x09, 0xAC, 0xC6, 0x9F, 0x82, 0x1C, 0x05,
            0x46, 0xC2, 0x34, 0x3C, 0x0D, 0x3B, 0xCE, 0xB7, 0xBE, 0x08, 0x9C,
            0x6B, 0xEE, 0xE5, 0x87, 0xAF, 0xBF, 0xF2, 0xEB, 0x7B, 0x07, 0x64,
            0xC5, 0xB6, 0xAE, 0x9A, 0x95, 0x35, 0xA5, 0x59, 0x12, 0x9E, 0xA3,
            0xB8, 0x8E, 0x5A, 0xF7, 0x62, 0xD2, 0x3A, 0xA8, 0x7D, 0x85, 0xF6,
            0xC8, 0x71, 0x29, 0xD6, 0xD7, 0x43, 0xF9, 0x78, 0x76, 0x73, 0x10,
            0x91, 0x19, 0x0A, 0x99, 0xF0, 0xE6, 0x3F, 0x14, 0xF1, 0xE2, 0xB1,
            0x86, 0xB4, 0xF3, 0x74, 0xFA, 0x6A, 0xB2, 0x21, 0x6D, 0xEA, 0xB5,
            0xE7, 0xE3, 0xC9, 0xD3, 0x8F, 0x03, 0x75, 0xE8, 0xD4, 0x42, 0xFD,
            0x7E, 0xFF, 0x7F
        ])
        S = [SBox_CVL(sb, name=f"HURDLE-S{i}") for i in range(12)]

        sbox_nodes = [None for _ in range(12)]
        sbox_nodes[11] = hurdle_f.add_subcipher(S[11], [
            (rk_adds[11], (j, j)) for j in range(2)
        ])

        for i in range(10, -1, -1):
            xor = XOR_CVL(8, name=f"xor{i}")
            node = hurdle_f.add_subcipher(xor, [
                (rk_adds[i], (j, j)) for j in range(2)
            ] + [
                (sbox_nodes[i + 1], (j, j + 2)) for j in range(2)
            ])

            sbox_nodes[i] = hurdle_f.add_subcipher(S[i], [
                (node, (j, j)) for j in range(2)
            ])

        perm = [
            0, 4,  8, 12, 16, 20, 24, 28,
            1, 5,  9, 13, 17, 21, 25, 29,
            2, 6, 10, 14, 18, 22, 26, 30,
            3, 7, 11, 15, 19, 23, 27, 31
        ]
        P = PermuteLayer_CVL([perm[i] for i in range(32)], name="P").inv()

        node_perm = hurdle_f.add_subcipher(P, [
            (sbox_nodes[i], (1, i)) for i in range(8)
        ])
        hurdle_f.add_output([(node_perm, (i, i)) for i in range(8)])

        self.cipher = hurdle_f

    def __new__(cls, *args, **kwargs):
        instance = super(HURDLE_F_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher


class HURDLE_CVL:
    def __init__(self, R=16, k=None, name=None) -> None:
        r"""
        Implementation of the HURDLE cipher, imitating MidnightBlue's
        implementation.

        TESTS::

        Test HURDLE-F from the outside:

            sage: from civerly.cipher_implementations.hurdle import HURDLE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: hurdle_f = HURDLE_CVL(
            ....:   R=1, k=0x99990099991188992277993366994455
            ....:   ).nodes[1].nodes[1]
            sage: vec_to_int(hurdle_f(int_to_vec(0x2222eeee, 32))) == \
            ....:   0x2bee4c18
            True

        Test round-reduced versions of HURDLE-II:

            sage: from civerly.cipher_implementations.hurdle import HURDLE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: hurdle = HURDLE_CVL(R=1, k=0x99990099991188992277993366994455)
            sage: vec_to_int(hurdle(int_to_vec(0x222266662222eeee, 64))) == \
            ....:   0x09cc2a7e2222eeee
            True
            sage: from civerly.cipher_implementations.hurdle import HURDLE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: hurdle = HURDLE_CVL(R=2, k=0xabcdef12c001f00ddeadbeefcafebabe)
            sage: vec_to_int(hurdle(int_to_vec(0xcafebabedeadbeef, 64))) == \
            ....:   0x01451285643ddd6f
            True

        Test full round HURDLE-II:

            sage: from civerly.cipher_implementations.hurdle import HURDLE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: hurdle = HURDLE_CVL(
            ....:   R=16, k=0x99990099991188992277993366994455)
            sage: vec_to_int(hurdle(int_to_vec(0x222266662222eeee, 64))) == \
            ....:   0xb4da6698d36b1652
            True
            sage: from civerly.cipher_implementations.hurdle import HURDLE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: hurdle = HURDLE_CVL(
            ....:   R=16, k=0xabcdef12c001f00ddeadbeefcafebabe)
            sage: vec_to_int(hurdle(int_to_vec(0xcafebabedeadbeef, 64))) == \
            ....:   0x4bf15508812e06f0
            True

        Model 4 rounds HURDLE-II:

            sage: from civerly.cipher_implementations.hurdle import HURDLE_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: cipher = HURDLE_CVL(R=4)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cadical  # optional - espresso
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:       sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:       logic_minimizer=ESPRESSO_CVL(),
            ....:       sat_solver=CADICAL_CVL(),
            ....:       path=Path(tmpdir)
            ....:   )
            ....:   cipher.analyse(model_options)
            7168 variables and 88545 clauses were written to ...
            12

        """

        if name is None:
            name = "HURDLE-II"

        cipher = WordBasedCipher(4, 16, 16, name=name)

        round_node = cipher.IN
        for r in range(R):

            hurdle_f = HURDLE_F_CVL(rk=0)

            # build feistel round
            hurdle_round = WordBasedCipher(4, 16, 16, name="round")
            node = hurdle_round.add_subcipher(
                hurdle_f, [(hurdle_round.IN, (i + 8, i)) for i in range(8)]
            )
            feistel_xor = XOR_CVL(32, name="feistel_xor")
            node = hurdle_round.add_subcipher(feistel_xor, [
                (hurdle_round.IN, (i, i)) for i in range(8)
            ] + [
                (node, (i, i + 8)) for i in range(8)
            ])
            hurdle_round.add_output([(node, (i, i + 8)) for i in range(8)])
            hurdle_round.add_output(
                [(hurdle_round.IN, (i + 8, i)) for i in range(8)]
            )
            round_node = cipher.add_subcipher(
                hurdle_round, [(round_node, (i, i)) for i in range(16)]
            )

        # final swap (as in MidnightBlue's implementation)
        cipher.add_output([(round_node, (i, (i + 8) % 16)) for i in range(16)])

        # collect RK references after deepcopying is complete
        cipher._rk_components = [cipher.nodes[r+1].nodes[1].nodes[1] for r in range(R)]
        cipher.key_schedule = hurdle_key_schedule

        self.cipher = cipher

        if k is not None:
            cipher.set_round_keys(k)

    def __new__(cls, *args, **kwargs):
        instance = super(HURDLE_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
