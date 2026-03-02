from sage.crypto.sbox import SBox
from civerly.sboxcipher import SBoxCipher
from civerly.component import SBox_CVL


# cipher using different sbox sizes in one layer
class Toy7:
    def __init__(self):
        r"""

        TESTS::

        The test code for SAT:

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.toy_ciphers.toy7 \
            ....:   import Toy7
            sage: from civerly.model_options import *
            sage: cipher = Toy7()
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:   sat_solver=CRYPTOMINISAT_CVL(),
            ....:   logic_minimizer=ESPRESSO_CVL(),
            ....:   solve_range=(0, 8),
            ....:   path=Path("./DOCTEST-Toy7-Models/"))
            sage: cipher.analyse(model_options=model_options)
            Using existing file DOCTEST-Toy7-Models/espresso-4ce399fb_out.pla,
            make sure it is up to date!
            Using existing file DOCTEST-Toy7-Models/espresso-4ce399fb_out.pla,
            make sure it is up to date!
            Using existing file DOCTEST-Toy7-Models/espresso-d3ba4659_out.pla,
            make sure it is up to date!
            1356 variables and 3621 clauses were written to
            'DOCTEST-Toy7-Models/Toy7.cnf'
            [  0 ,  8] (trying w =   4) : SAT
            [  0 ,  4] (trying w =   2) : UNSAT
            [  3 ,  4] (trying w =   3) : SAT
            3
            sage: cipher.generate_report(model_options)
            Output file in: DOCTEST-Toy7-Models/Toy7.pdf
            sage: trail = str(cipher.get_trail(model_options))
            sage: assert "Unnamed Component" not in trail
            sage: import shutil
            sage: shutil.rmtree("DOCTEST-Toy7-Models", ignore_errors=True)

        """

        cipher = SBoxCipher(24, 64, name="Toy7")

        # 2 -> 3
        S1 = SBox_CVL(SBox((6, 2, 5, 1)), name="S(2 -> 3)")
        S2 = SBox_CVL(SBox(
            (2, 11, 7, 0, 16, 20, 4, 28, 23, 8, 3, 6, 27, 21, 6, 19)
        ), name="S(4 -> 5)")

        round1 = SBoxCipher(24, 36, name="round1")
        for j in range(12):
            node = round1.add_subcipher(S1, [(round1.IN, (i+2*j, i)) for i in range(2)])
            round1.add_output([(node, (i, i+3*j)) for i in range(3)])

        round2 = SBoxCipher(36, 48, name="round2")
        j, k, jj = 0, 0, 0
        while j < 36:
            node = round2.add_subcipher(S1, [(round2.IN, (i+j, i)) for i in range(2)])
            round2.add_output([(node, (i, i+jj)) for i in range(3)])
            k += 1
            j += 2
            jj += 3
            node = round2.add_subcipher(S2, [(round2.IN, (i+j, i)) for i in range(4)])
            round2.add_output([(node, (i, i+jj)) for i in range(5)])
            k += 1
            j += 4
            jj += 5

        round3 = SBoxCipher(48, 64, name="round3")
        j, k, jj = 0, 0, 0
        while j < 48:
            node = round3.add_subcipher(S1, [(round3.IN, (i+j, i)) for i in range(2)])
            round3.add_output([(node, (i, i+jj)) for i in range(3)])
            k += 1
            j += 2
            jj += 3
            node = round3.add_subcipher(S2, [(round3.IN, (i+j, i)) for i in range(4)])
            round3.add_output([(node, (i, i+jj)) for i in range(5)])
            k += 1
            j += 4
            jj += 5

        P36 = [
            17, 6, 13, 30, 32, 5, 3, 8, 34, 12, 9, 1, 27, 28, 14, 10, 18, 16,
            25, 20, 35, 19, 31, 15, 23, 21, 7, 4, 22, 24, 0, 2, 26, 29, 33, 11
        ]
        P48 = [
            17, 8, 15, 11, 2, 10, 33, 19, 38, 45, 3, 30, 7, 26, 34, 0, 35, 1,
            39, 40, 27, 29, 20, 41, 47, 4, 37, 46, 36, 9, 6, 32, 21, 24, 18,
            43, 31, 23, 25, 22, 12, 14, 44, 16, 5, 42, 28, 13
        ]

        node = cipher.IN
        node = cipher.add_subcipher(round1, [(node, (i, i)) for i in range(24)])
        node = cipher.add_subcipher(round2, [(node, (i, P36[i])) for i in range(36)])
        node = cipher.add_subcipher(round3, [(node, (i, P48[i])) for i in range(48)])
        cipher.add_output([(node, (i, i)) for i in range(64)])

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(Toy7, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
