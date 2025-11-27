from sage.rings.finite_rings.finite_field_constructor import GF
from sage.matrix.constructor import Matrix as matrix
from sage.crypto.sbox import SBox as SBox_sage
from sage.crypto.sboxes import DES_S1_1, DES_S1_2, DES_S1_3, DES_S1_4
from sage.crypto.sboxes import DES_S2_1, DES_S2_2, DES_S2_3, DES_S2_4
from sage.crypto.sboxes import DES_S3_1, DES_S3_2, DES_S3_3, DES_S3_4
from sage.crypto.sboxes import DES_S4_1, DES_S4_2, DES_S4_3, DES_S4_4
from sage.crypto.sboxes import DES_S5_1, DES_S5_2, DES_S5_3, DES_S5_4
from sage.crypto.sboxes import DES_S6_1, DES_S6_2, DES_S6_3, DES_S6_4
from sage.crypto.sboxes import DES_S7_1, DES_S7_2, DES_S7_3, DES_S7_4
from sage.crypto.sboxes import DES_S8_1, DES_S8_2, DES_S8_3, DES_S8_4

from civerly.sboxcipher import SBoxCipher
from civerly.component import LinearLayer_CVL, PermuteLayer_CVL, XOR_CVL
from civerly.component import SBox_CVL, RoundkeyXOR_CVL


class DES_F_CVL:
    def __init__(self):
        r"""
        The implementation of DES-F.
        The test vectors are taken from
        https://crypto.stackexchange.com/questions/65996/64-des-full-example-with-all-the-stages.

        TESTS::

            sage: from civerly.util import vec_to_int, int_to_vec
            sage: from civerly.cipher_implementations.des import DES_F_CVL
            sage: des_f = DES_F_CVL()
            sage: des_f.nodes[2].const = 0x0B02679B49A5
            sage: vec_to_int(des_f(int_to_vec(0x00FE1327, 32))) == 0x7E4B644F
            True
            sage: des_f.nodes[2].const = 0x69A659256A26
            sage: vec_to_int(des_f(int_to_vec(0xC9EFE379, 32))) == 0xC2DBC430
            True

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.des import DES_F_CVL
            sage: from civerly.model_options import *
            sage: cipher = DES_F_CVL()
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:   sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:   solver=SOLVER.CRYPTOMINISAT,
            ....:   solve_range=(0, 4),
            ....:   path=Path("DOCTEST-DESF-Models"))
            sage: cipher.analyse(model_options=model_options)
            582 variables and 4612 clauses were written to
            'DOCTEST-DESF-Models/f.cnf'
            [  0 ,  4] (trying w =   2) : SAT
            [  0 ,  2] (trying w =   1) : UNSAT
            2

            sage: # optional - cadical # optional - espresso
            sage: from civerly.cipher_implementations.des import DES_F_CVL
            sage: from civerly.model_options import *
            sage: cipher = DES_F_CVL()
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:   sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:   solver=SOLVER.CADICAL,
            ....:   solve_range=(0, 4),
            ....:   path=Path("DOCTEST-DESF-Models"))
            sage: cipher.analyse(model_options=model_options)
            582 variables and 4612 clauses were written to
            'DOCTEST-DESF-Models/f.cnf'
            [  0 ,  4] (trying w =   2) : SAT
            [  0 ,  2] (trying w =   1) : UNSAT
            2

        Using MILP modeling::

            sage: from civerly.cipher_implementations.des import DES_F_CVL
            sage: from civerly.model_options import *
            sage: cipher = DES_F_CVL()
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.MILP,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:   sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:   solver=SOLVER.GUROBI,
            ....:   path=Path("DOCTEST-DESF-Models"))
            sage: # optional - gurobi # optional - espresso
            sage: cipher.analyse(model_options=model_options)
            630 variables and 4164 constraints were written to
            'DOCTEST-DESF-Models/f.mps'
            2
            sage: cipher.generate_report(model_options=model_options)
            Output file in: DOCTEST-DESF-Models/f.pdf

            sage: import shutil
            sage: shutil.rmtree("DOCTEST-DESF-Models", ignore_errors=True)

        """
        f = SBoxCipher(32, 32, name="f")

        e_table = [
            32,  1,  2,  3,  4,  5,
            4,  5,  6,  7,  8,  9,
            8,  9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32,  1
        ]
        arr = [[0 for _ in range(32)] for _ in range(len(e_table))]
        for i in range(len(e_table)):
            arr[i][e_table[i] - 1] = 1

        E = LinearLayer_CVL(matrix(GF(2), arr), name="E")

        S_arr = [
            [DES_S1_1, DES_S1_2, DES_S1_3, DES_S1_4],
            [DES_S2_1, DES_S2_2, DES_S2_3, DES_S2_4],
            [DES_S3_1, DES_S3_2, DES_S3_3, DES_S3_4],
            [DES_S4_1, DES_S4_2, DES_S4_3, DES_S4_4],
            [DES_S5_1, DES_S5_2, DES_S5_3, DES_S5_4],
            [DES_S6_1, DES_S6_2, DES_S6_3, DES_S6_4],
            [DES_S7_1, DES_S7_2, DES_S7_3, DES_S7_4],
            [DES_S8_1, DES_S8_2, DES_S8_3, DES_S8_4]
        ]

        S_new = []

        for n, sb in enumerate(S_arr):
            S_new.append([])
            for i in range(64):
                S_new[n].append(
                    sb[(((i >> 5) & 1) << 1) | (i & 1)][(i >> 1) & 0xf]
                )

        # SBox_CVL is CiVerLy component, SBox_sage is SageMath-SBox object
        S = [SBox_CVL(SBox_sage(s), name=f"S{i}") for i, s in enumerate(S_new)]
        P_perm = [
            16,  7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2,  8, 24, 14,
            32, 27,  3,  9,
            19, 13, 30,  6,
            22, 11,  4, 25
        ]
        permute = PermuteLayer_CVL([p-1 for p in P_perm], name="P").inv()
        key_add = RoundkeyXOR_CVL(48, 0x0, name="key_add")

        # ---------------------------- F ------------------------------------ #
        e_node = f.add_subcipher(
            E, [(f.IN, (i, i)) for i in range(32)]
        )
        rk_node = f.add_subcipher(
            key_add, [(e_node, (i, i)) for i in range(48)]
        )
        s_nodes = [f.add_subcipher(
            S[s], [(rk_node, (i + 6*s, i)) for i in range(6)])
            for s in range(8)
        ]
        p_node = f.add_subcipher(
            permute, [
                (nod, (i, i + 4*n))
                for i in range(4)
                for n, nod in enumerate(s_nodes)
            ]
        )
        f.add_output([(p_node, (i, i)) for i in range(32)])
        # ------------------------------------------------------------------- #
        self.f = f

    def __new__(cls, *args, **kwargs):
        instance = super(DES_F_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.f


class DES_CVL:
    def __init__(self, R, rks=[], name=None) -> None:
        r"""
        The DES implementation.
        The test vectors are taken from https://crypto.stackexchange.com/questions/65996/64-des-full-example-with-all-the-stages.

        TESTS::

            sage: from civerly.cipher_implementations.des import DES_CVL
            sage: from civerly.util import vec_to_int, int_to_vec
            sage: rks = [
            ....:   0x0B02679B49A5, 0x69A659256A26, 0x45D48AB428D2,
            ....:   0x7289D2A58257, 0x3CE80317A6C2, 0x23251E3C8545,
            ....:   0x6C04950AE4C6, 0x5788386CE581, 0xC0C9E926B839,
            ....:   0x91E307631D72, 0x211F830D893A, 0x7130E5455C54,
            ....:   0x91C4D04980FC, 0x5443B681DC8D, 0xB691050A16B5,
            ....:   0xCA3D03B87032
            ....: ]
            sage: des = DES_CVL(R=16, rks=rks)
            sage: vec_to_int(des(int_to_vec(0x4E6F772069732074, 64))) \
            ....:   == 0x3FA40E8A984D4815
            True
            sage: vec_to_int(des(int_to_vec(0x68652074696D6520, 64))) \
            ....:   == 0x6A271787AB8883F9
            True
            sage: vec_to_int(des(int_to_vec(0x666F7220616C6C20, 64))) \
            ....:   == 0x893D51EC4B563B53
            True

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.des import DES_CVL
            sage: from civerly.model_options import *
            sage: cipher = DES_CVL(R=3)
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:   sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:   solver=SOLVER.CRYPTOMINISAT,
            ....:   solve_range=(0, 10),
            ....:   path=Path("DOCTEST-DES-Models"))
            sage: cipher.analyse(model_options=model_options)
            3826 variables and 18250 clauses were written to
            'DOCTEST-DES-Models/DES.cnf'
            [  0 , 10] (trying w =   5) : SAT
            [  0 ,  5] (trying w =   2) : UNSAT
            [  3 ,  5] (trying w =   4) : SAT
            [  3 ,  4] (trying w =   3) : UNSAT
            4
            sage: trail = str(cipher.get_trail(model_options))
            sage: assert "Unnamed Component" not in trail
            sage: import shutil
            sage: shutil.rmtree("DOCTEST-DES-Models", ignore_errors=True)

        """
        if name is None:
            name = "DES"

        if rks == []:
            rks = [0 for _ in range(R)]  # default to zero keys

        des = SBoxCipher(64, 64, name=name)
        xor = XOR_CVL(32, name="XOR")
        round_function = SBoxCipher(64, 64, name="Round")

        ip_arr = [
            57, 49, 41, 33, 25, 17, 9,  1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7,
            56, 48, 40, 32, 24, 16, 8,  0,
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6
        ]
        ip = PermuteLayer_CVL(ip_arr, name="IP").inv()

        f = DES_F_CVL()

        # ------------------------- Round Function -------------------------- #
        f_node = round_function.add_subcipher(
            f, [(round_function.IN, (i + 32, i)) for i in range(32)]
        )
        xor_node = round_function.add_subcipher(
            xor,
            [
                (f_node, (i, i)) for i in range(32)
            ] + [
                (round_function.IN, (i, i + 32)) for i in range(32)
            ]
        )

        round_function.add_output(
            [(round_function.IN, (i + 32, i)) for i in range(32)]
        )
        round_function.add_output(
            [(xor_node, (i, i + 32)) for i in range(32)]
        )
        # ------------------------------------------------------------------- #

        # ----------------------------- DES --------------------------------- #
        current = des.add_subcipher(ip, [(des.IN, (i, i)) for i in range(64)])
        for r in range(R):
            round_function.nodes[f_node].nodes[2].const = rks[r]
            current = des.add_subcipher(
                round_function, [(current, (i, i)) for i in range(64)]
            )
        current = des.add_subcipher(
            ip.inv(), [(current, ((i + 32) % 64, i)) for i in range(64)]
        )
        des.add_output([(current, (i, i)) for i in range(64)])
        # ------------------------------------------------------------------- #

        self.des = des

    def __new__(cls, *args, **kwargs):
        instance = super(DES_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.des
