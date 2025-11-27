from civerly.addrx import AddRX
from civerly.component import RotateLayer_CVL, ModAdd_CVL, XOR_CVL
from civerly.component import PermuteLayer_CVL, C_CVL

# ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~- #
#   Building Chacha QRF in CiVerLy
# ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~- #


class ChachaQRF_CVL:
    def __init__(self, name=None):
        r"""
        The CiVerLy implementation of the Chacha QRF. Since there is nothing
        to tweak, it does not take any parameters. This cipher is
        "plug-and-play" usable, i.e. it can be directly used when imported.

        EXAMPLES::

            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.chacha \
            ....:   import ChachaQRF_CVL
            sage: qrf = ChachaQRF_CVL()
            sage: hex(vec_to_int(qrf(int_to_vec(0x12345678, 128))))
            '0x812345677611b618b1cf660b5b5753d7'
            sage: hex(vec_to_int(qrf(int_to_vec(
            ....:   0xaeaeaea0_aeaeaea1_aeaeaea2_aeaeaea3,
            ....: 128))))
            '0x4e209e041e6d48ca64ff9a52c26df7bd'

        TESTS::

            sage: from civerly.cipher_implementations.chacha \
            ....:   import ChachaQRF_CVL
            sage: from civerly.model_options import *
            sage: cipher = ChachaQRF_CVL()
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   solver=SOLVER.CRYPTOMINISAT,
            ....:   solve_range=(0, 8),
            ....:   path=Path("./DOCTEST-ChachaQRF-Models/"))
            sage: # optional - cryptominisat
            sage: cipher.analyse(model_options=model_options)
            1916 variables and 4957 clauses were written to
            'DOCTEST-ChachaQRF-Models/Chacha-QRF.cnf'
            [  0 ,  8] (trying w =   4) : SAT
            [  0 ,  4] (trying w =   2) : SAT
            [  0 ,  2] (trying w =   1) : SAT
            [  0 ,  1] (trying w =   0) : SAT
            0
            sage: cipher.generate_report(model_options)
            Output file in: DOCTEST-ChachaQRF-Models/Chacha-QRF.pdf
            sage: trail = str(cipher.get_trail(model_options))
            sage: assert "Unnamed Component" not in trail

            sage: from civerly.cipher_implementations.chacha \
            ....:   import ChachaQRF_CVL
            sage: from civerly.model_options import *
            sage: cipher = ChachaQRF_CVL()
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   solver=SOLVER.CADICAL,
            ....:   solve_range=(0, 8),
            ....:   path=Path("./DOCTEST-ChachaQRF-Models/"))
            sage: # optional - cadical
            sage: cipher.analyse(model_options=model_options)
            1916 variables and 4957 clauses were written to
            'DOCTEST-ChachaQRF-Models/Chacha-QRF.cnf'
            [  0 ,  8] (trying w =   4) : SAT
            [  0 ,  4] (trying w =   2) : SAT
            [  0 ,  2] (trying w =   1) : SAT
            [  0 ,  1] (trying w =   0) : SAT
            0
            sage: cipher.generate_report(model_options)
            Output file in: DOCTEST-ChachaQRF-Models/Chacha-QRF.pdf
            sage: trail = str(cipher.get_trail(model_options))
            sage: assert "Unnamed Component" not in trail

            sage: from civerly.cipher_implementations.chacha \
            ....:   import ChachaQRF_CVL
            sage: from civerly.model_options import *
            sage: cipher = ChachaQRF_CVL()
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   solver=SOLVER.CRYPTOMINISAT,
            ....:   path=Path("./DOCTEST-ChachaQRF-Models/"))
            sage: # optional - cryptominisat
            sage: cipher.analyse(model_options=model_options)
            1920 variables and 5797 clauses were written to
            'DOCTEST-ChachaQRF-Models/Chacha-QRF.cnf'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : SAT
            [  0 ,  6] (trying w =   3) : SAT
            [  0 ,  3] (trying w =   1) : SAT
            [  0 ,  1] (trying w =   0) : SAT
            0

            sage: import shutil
            sage: shutil.rmtree(
            ....:   "DOCTEST-ChachaQRF-Models", ignore_errors=True)

        """
        if name is None:
            name = "Chacha-QRF"
        chacha_qr = AddRX(32, 4, 4, name=name)

        add = ModAdd_CVL(32, name="add")
        rot16 = RotateLayer_CVL(32, 16, name="rot16")
        rot12 = RotateLayer_CVL(32, 12, name="rot12")
        rot8 = RotateLayer_CVL(32, 8, name="rot8")
        rot7 = RotateLayer_CVL(32, 7, name="rot7")
        xor = XOR_CVL(32, name="xor")

        # Components of QRF
        a0 = chacha_qr.add_subcipher(
            add, [(chacha_qr.IN, (0, 0)), (chacha_qr.IN, (1, 1))]
        )
        d1 = chacha_qr.add_subcipher(
            xor, [(a0, (0, 0)), (chacha_qr.IN, (3, 1))]
        )
        d2 = chacha_qr.add_subcipher(rot16, [(d1, (0, 0))])
        c3 = chacha_qr.add_subcipher(
            add, [(chacha_qr.IN, (2, 0)), (d2, (0, 1))]
        )
        b4 = chacha_qr.add_subcipher(
            xor, [(chacha_qr.IN, (1, 0)), (c3, (0, 1))]
        )
        b5 = chacha_qr.add_subcipher(rot12, [(b4, (0, 0))])
        a6 = chacha_qr.add_subcipher(add, [(a0, (0, 0)), (b5, (0, 1))])
        d7 = chacha_qr.add_subcipher(xor, [(a6, (0, 0)), (d2, (0, 1))])
        d8 = chacha_qr.add_subcipher(rot8, [(d7, (0, 0))])
        c9 = chacha_qr.add_subcipher(add, [(d8, (0, 0)), (c3, (0, 1))])
        ba = chacha_qr.add_subcipher(xor, [(c9, (0, 0)), (b5, (0, 1))])
        bb = chacha_qr.add_subcipher(rot7, [(ba, (0, 0))])

        chacha_qr.add_output([
            (a6, (0, 0)), (bb, (0, 1)), (c9, (0, 2)), (d8, (0, 3))
        ])

        self.chacha_qr = chacha_qr

    def __new__(cls, *args, **kwargs):
        instance = super(ChachaQRF_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.chacha_qr


class Chacha_CVL:
    def __init__(self, R=20, name=None):
        r"""
        The CiVerLy implementation of the Chacha QRF. It takes the
        following arguments:

            - ``R`` -- integer; Number of rounds.

        This cipher is "plug-and-play" usable, i.e. it can be directly
        used when imported.

        EXAMPLES::

            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.chacha import Chacha_CVL
            sage: chacha = Chacha_CVL(10)
            sage: hex(vec_to_int(chacha(int_to_vec(0x12345678, 384))))
            '0x830ea31f9682b3636956bd110cc048c79cc417bfa8f4bf073478c1627a57a6636b5722956e674b993b8f0622d1a5e0ed5cc62d7a23d03d82a08cd38fb7fae35e'
            sage: chacha_cipher = Chacha_CVL(20)
            sage: hex(vec_to_int(chacha_cipher(int_to_vec(0xaeaeaea0aeaeaea1aeaeaea2aeaeaea3_aeaeaea4aeaeaea5aeaeaea6aeaeaea7_aeaeaea8aeaeaea9aeaeaeaAaeaeaeaB, 384))))
            '0x7b435b3af7b4f2ef11672cb917259cb6f218b24ca321714fe1c2dc6f628b75de65cffb65d6c83b2f029f9e0e3143f5da905e5da7e3b2643f4b07c630011873be'

        TESTS::

            sage: from civerly.cipher_implementations.chacha import Chacha_CVL
            sage: from civerly.model_options import *
            sage: cipher = Chacha_CVL(1)
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   solver=SOLVER.CRYPTOMINISAT,
            ....:   solve_range=(0, 4),
            ....:   path=Path("./DOCTEST-Chacha-Models/"))
            sage: # optional - cryptominisat
            sage: cipher.analyse(model_options=model_options)
            22240 variables and 53601 clauses were written to
            'DOCTEST-Chacha-Models/Chacha.cnf'
            [  0 ,  4] (trying w =   2) : SAT
            [  0 ,  2] (trying w =   1) : UNSAT
            2
            sage: import shutil
            sage: shutil.rmtree("DOCTEST-Chacha-Models", ignore_errors=True)



        """
        if name is None:
            name = "Chacha"
        chacha_qr = ChachaQRF_CVL()

        # ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~ #
        #   Building Chacha from the QRFs in CiVerLy
        # ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~ #

        # ------------------------------------------------------------------- #
        # Chacha accepts a 256-bit key + 128-bit IV, which is
        # 12 words x 32 bits. It further outputs a 512-bit state,
        # which is 16 words x 32 bits.
        chacha_cipher = AddRX(32, 12, 16, name=name)
        # ------------------------------------------------------------------- #

        # permute_..._round is used for switching between columns and diagonals
        permute_even_round = PermuteLayer_CVL(
            [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3],
            word_coarseness=32,
            name="perm-odd"
        )
        permute_odd_round = PermuteLayer_CVL(
            [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11],
            word_coarseness=32,
            name="perm-even"
        )
        initial_perm = PermuteLayer_CVL(
            [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15],
            word_coarseness=32,
            name="transpose"
        )
        # initial_perm is used for transposing (since the QRF is applied
        # on columns, while we read the input row by row)

        # 4x QRF in parallel
        # ------------------------------------------------------------------- #

        fourtimes_qr = AddRX(32, 16, 16, name="4xQRF")
        for j in range(4):
            output_node = fourtimes_qr.add_subcipher(
                chacha_qr, [(fourtimes_qr.IN, (i + 4*j, i)) for i in range(4)]
            )
            fourtimes_qr.add_output(
                [(output_node, (i, i + 4*j)) for i in range(4)]
            )
        # ------------------------------------------------------------------- #

        constants = C_CVL(
            128, 0x61707865_3320646e_79622d32_6b206574, name="Chacha-const"
        )

        # ------------------------------------------------------------------- #
        final_add = AddRX(32, 32, 16, name="final-add")
        for j in range(16):
            node = final_add.add_subcipher(
                ModAdd_CVL(32, name="add"),
                [(final_add.IN, (j, 0)), (final_add.IN, (j+16, 1))]
            )
            final_add.add_output([(node, (0, j))])
        # ------------------------------------------------------------------- #

        # ------------------------------------------------------------------- #
        current_node = chacha_cipher.add_subcipher(constants, [])
        current_node = chacha_cipher.add_subcipher(
            initial_perm, [
                (current_node, (i, i)) for i in range(4)
            ] + [
                (chacha_cipher.IN, (i, i + 4)) for i in range(12)
            ]
        )
        initial_node = current_node
        for r in range(1, R + 1):

            if r & 1 == 0:
                current_node = chacha_cipher.add_subcipher(
                    permute_even_round,
                    [(current_node, (i, i)) for i in range(16)]
                )
            elif r != 1:
                current_node = chacha_cipher.add_subcipher(
                    permute_odd_round,
                    [(current_node, (i, i)) for i in range(16)]
                )
            current_node = chacha_cipher.add_subcipher(
                fourtimes_qr,
                [(current_node, (i, i)) for i in range(16)]
            )

        # Fix the alignment at the end (from diagonal to columns)
        if R & 1 == 0 and R > 0:
            current_node = chacha_cipher.add_subcipher(
                permute_odd_round, [(current_node, (i, i)) for i in range(16)]
            )

        current_node = chacha_cipher.add_subcipher(
            final_add,
            [
                (initial_node, (i, i)) for i in range(16)
            ] + [
                (current_node, (i, i + 16)) for i in range(16)
            ]
        )
        current_node = chacha_cipher.add_subcipher(
            initial_perm, [(current_node, (i, i)) for i in range(16)]
        )
        chacha_cipher.add_output([(current_node, (i, i)) for i in range(16)])
        # ------------------------------------------------------------------- #

        self.chacha_cipher = chacha_cipher

    def __new__(cls, *args, **kwargs):
        instance = super(Chacha_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.chacha_cipher
