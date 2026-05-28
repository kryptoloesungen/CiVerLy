from sage.crypto.sbox import SBox
from civerly.sboxcipher import SBoxCipher
from civerly.component import PermuteLayer_CVL, SBox_CVL, RotateLayer_CVL
from civerly.component import RoundkeyXOR_CVL, XOR_CVL


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
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir)
            ....:   )
            ....:   abc_cipher.analyse(model_options)
            12640 variables and 44257 clauses were written to '...'
            [  0 , 10] (trying w =   5) : SAT
            [  0 ,  5] (trying w =   2) : UNSAT
            [  3 ,  5] (trying w =   4) : SAT
            [  3 ,  4] (trying w =   3) : SAT
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
                RotateLayer_CVL(8, j, name=f"r{j}"), [(smallR.IN, (i + 8*j, i)) for i in range(8)]
            )
            smallR.add_output([(node, (i, i + 8*j)) for i in range(8)])

        sb = SBox_CVL(SBox([
            0x4, 0xc, 0x0, 0x8, 0x6, 0xe, 0x1, 0xb,
            0x9, 0xd, 0x2, 0x5, 0xa, 0xf, 0x3, 0x7
        ]), name="S")
        sb_layer = SBoxCipher(64, 64, name="S-Layer")
        for j in range(16):
            node = sb_layer.add_subcipher(sb, [
                (sb_layer.IN, (i + 4*j, i)) for i in range(4)
            ])
            sb_layer.add_output([(node, (i, i + 4*j)) for i in range(4)])

        bs = SBox_CVL(SBox([
            0x9b, 0x9e, 0xa1, 0xa4, 0xa7, 0xaa, 0xad, 0xb0, 0xb3, 0xb6, 0xb9,
            0xbc, 0xbf, 0xc2, 0xc5, 0xc8, 0xcb, 0xce, 0xd1, 0xd4, 0xd7, 0xda,
            0xdd, 0xe0, 0xe3, 0xe6, 0xe9, 0xec, 0xef, 0xf2, 0xf5, 0xf8, 0xfb,
            0xfe, 0x01, 0x04, 0x07, 0x0a, 0x0d, 0x10, 0x13, 0x16, 0x19, 0x1c,
            0x1f, 0x22, 0x25, 0x28, 0x2b, 0x2e, 0x31, 0x34, 0x37, 0x3a, 0x3d,
            0x40, 0x43, 0x46, 0x49, 0x4c, 0x4f, 0x52, 0x55, 0x58, 0x5b, 0x5e,
            0x61, 0x64, 0x67, 0x6a, 0x6d, 0x70, 0x73, 0x76, 0x79, 0x7c, 0x7f,
            0x82, 0x85, 0x88, 0x8b, 0x8e, 0x91, 0x94, 0x97, 0x9a, 0x9d, 0xa0,
            0xa3, 0xa6, 0xa9, 0xac, 0xaf, 0xb2, 0xb5, 0xb8, 0xbb, 0xbe, 0xc1,
            0xc4, 0xc7, 0xca, 0xcd, 0xd0, 0xd3, 0xd6, 0xd9, 0xdc, 0xdf, 0xe2,
            0xe5, 0xe8, 0xeb, 0xee, 0xf1, 0xf4, 0xf7, 0xfa, 0xfd, 0x00, 0x03,
            0x06, 0x09, 0x0c, 0x0f, 0x12, 0x15, 0x18, 0x1b, 0x1e, 0x21, 0x24,
            0x27, 0x2a, 0x2d, 0x30, 0x33, 0x36, 0x39, 0x3c, 0x3f, 0x42, 0x45,
            0x48, 0x4b, 0x4e, 0x51, 0x54, 0x57, 0x5a, 0x5d, 0x60, 0x63, 0x66,
            0x69, 0x6c, 0x6f, 0x72, 0x75, 0x78, 0x7b, 0x7e, 0x81, 0x84, 0x87,
            0x8a, 0x8d, 0x90, 0x93, 0x96, 0x99, 0x9c, 0x9f, 0xa2, 0xa5, 0xa8,
            0xab, 0xae, 0xb1, 0xb4, 0xb7, 0xba, 0xbd, 0xc0, 0xc3, 0xc6, 0xc9,
            0xcc, 0xcf, 0xd2, 0xd5, 0xd8, 0xdb, 0xde, 0xe1, 0xe4, 0xe7, 0xea,
            0xed, 0xf0, 0xf3, 0xf6, 0xf9, 0xfc, 0xff, 0x02, 0x05, 0x08, 0x0b,
            0x0e, 0x11, 0x14, 0x17, 0x1a, 0x1d, 0x20, 0x23, 0x26, 0x29, 0x2c,
            0x2f, 0x32, 0x35, 0x38, 0x3b, 0x3e, 0x41, 0x44, 0x47, 0x4a, 0x4d,
            0x50, 0x53, 0x56, 0x59, 0x5c, 0x5f, 0x62, 0x65, 0x68, 0x6b, 0x6e,
            0x71, 0x74, 0x77, 0x7a, 0x7d, 0x80, 0x83, 0x86, 0x89, 0x8c, 0x8f,
            0x92, 0x95, 0x98
        ], name="BS"))

        bs_layer = SBoxCipher(64, 64, name="BS-Layer")
        for j in range(8):
            node = bs_layer.add_subcipher(bs, [
                (bs_layer.IN, (i + 8*j, i)) for i in range(8)
            ])
            bs_layer.add_output([(node, (i, i + 8*j)) for i in range(8)])

        node_rk = abc_round.add_subcipher(rk, [
            (abc_round.IN, (i + 64, i)) for i in range(64)
        ])
        node_s = abc_round.add_subcipher(sb_layer, [
            (node_rk, (i, i)) for i in range(64)
        ])
        node_r = abc_round.add_subcipher(smallR, [
            (node_s, (i, i)) for i in range(64)
        ])
        node_bigr = abc_round.add_subcipher(bigR, [
            (abc_round.IN, (i, i)) for i in range(64)
        ])
        node_xor = abc_round.add_subcipher(xor, [
            (node_r, (i, i)) for i in range(64)
        ] + [(node_bigr, (i, i + 64)) for i in range(64)])
        node_bs = abc_round.add_subcipher(bs_layer, [
            (node_xor, (i, i)) for i in range(64)
        ])

        abc_round.add_output([(node_bs, (i, i + 64)) for i in range(64)])
        abc_round.add_output([(abc_round.IN, (i + 64, i)) for i in range(64)])

        node = cipher.IN
        for r in range(R):
            abc_round.nodes[node_rk].const = rks[r]
            node = cipher.add_subcipher(abc_round, [
                (node, (i, i)) for i in range(128)
            ])
        cipher.add_output([(node, (i, i)) for i in range(128)])

        # Collect references to all RoundkeyXOR_CVL components for key schedule
        # support. Each entry points to the KeyAdd component inside the
        # corresponding round node. Set key_schedule to a callable returning
        # R round keys to enable set_round_keys(k).
        # ------------------------------------------------ #
        cipher._rk_components = [
            cipher.nodes[r+1].nodes[node_rk] for r in range(R)
        ]
        cipher.key_schedule = None

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(ABC_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
