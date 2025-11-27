from sage.matrix.constructor import Matrix as matrix
from sage.rings.finite_rings.finite_field_constructor import GF
from civerly.sboxcipher import SBoxCipher
from civerly.component import LinearLayer_CVL, PermuteLayer_CVL, XOR_CVL


# linear cipher with XOR_CVL component
class Toy4:
    def __init__(self):
        r"""

        TESTS::

        The test code for SAT:

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.toy_ciphers.toy4 \
            ....:   import Toy4
            sage: from civerly.model_options import *
            sage: cipher = Toy4()
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:   sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:   solver=SOLVER.CRYPTOMINISAT,
            ....:   path=Path("./DOCTEST-Toy4-Models/"))
            sage: cipher.analyse(model_options=model_options)
            288 variables and 1537 clauses were written to
            'DOCTEST-Toy4-Models/Toy4.cnf'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : SAT
            [  0 ,  6] (trying w =   3) : SAT
            [  0 ,  3] (trying w =   1) : SAT
            [  0 ,  1] (trying w =   0) : SAT
            0
            sage: cipher.generate_report(model_options)
            Output file in: DOCTEST-Toy4-Models/Toy4.pdf
            sage: trail = str(cipher.get_trail(model_options))
            sage: assert "Unnamed Component" not in trail

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.toy_ciphers.toy4 \
            ....:   import Toy4
            sage: from civerly.model_options import *
            sage: cipher = Toy4()
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:   sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:   solver=SOLVER.CRYPTOMINISAT,
            ....:   path=Path("./DOCTEST-Toy4-Models/"))
            sage: cipher.analyse(model_options=model_options)
            360 variables and 897 clauses were written to
            'DOCTEST-Toy4-Models/Toy4.cnf'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : SAT
            [  0 ,  6] (trying w =   3) : SAT
            [  0 ,  3] (trying w =   1) : SAT
            [  0 ,  1] (trying w =   0) : SAT
            0
            sage: cipher.generate_report(model_options)
            Output file in: DOCTEST-Toy4-Models/Toy4.pdf
            sage: trail = str(cipher.get_trail(model_options))
            sage: assert "Unnamed Component" not in trail

        The test code for MILP:

            sage: from civerly.cipher_implementations.toy_ciphers.toy4 \
            ....:   import Toy4
            sage: from civerly.model_options import *
            sage: cipher = Toy4()
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.MILP,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:   sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:   solver=SOLVER.GUROBI, \
            ....:   path=Path("./DOCTEST-Toy4-Models/"))
            sage: # optional - gurobi
            sage: cipher.analyse(model_options)
            376 variables and 305 constraints were written to
            'DOCTEST-Toy4-Models/Toy4.mps'
            0
            sage: trail = str(cipher.get_trail(model_options))
            sage: assert "Unnamed Component" not in trail

        The last line checks whether the ciphers last layer is represented
        correctly, even though it has a smaller width than the ciphers
        wordsize.
        Removing the files:
            sage: import shutil
            sage: shutil.rmtree("DOCTEST-Toy4-Models", ignore_errors=True)

        """
        cipher = SBoxCipher(32, 16, name="Toy4")
        arr = [
            [1, 0, 0, 1, 0, 1, 1, 1],
            [1, 1, 1, 1, 0, 1, 1, 1],
            [0, 0, 0, 0, 1, 0, 1, 0],
            [1, 1, 0, 1, 1, 1, 0, 0],
            [0, 1, 1, 1, 1, 0, 1, 0],
            [0, 0, 0, 1, 0, 0, 1, 0],
            [1, 0, 0, 1, 1, 0, 1, 0],
            [0, 1, 0, 1, 0, 1, 0, 1]
        ]
        mat = matrix(GF(2), 8, arr)

        xor = XOR_CVL(8, name="XOR(8)")
        node = [cipher.IN for j in range(4)]
        for j in range(4):
            Lj = LinearLayer_CVL(mat, name=f"L{j}(8)")
            node[j] = cipher.add_subcipher(
                Lj, [(node[j], (8*j + i, i)) for i in range(8)]
            )

        node_after_add1 = cipher.add_subcipher(
            xor,
            [(node[0], (i, (2*i) % 16)) for i in range(8)] +
            [(node[1], (i, (2*i + 1) % 16)) for i in range(8)]
        )
        node_after_add2 = cipher.add_subcipher(
            xor,
            [(node[2], (i, i)) for i in range(8)] +
            [(node[3], (i, i+8)) for i in range(8)]
        )

        P = PermuteLayer_CVL([1, 3, 0, 2], word_coarseness=2, name="P")

        node_1 = cipher.add_subcipher(
            P, [(node_after_add1, (i, i)) for i in range(8)]
        )
        node_2 = cipher.add_subcipher(
            P, [(node_after_add2, (i, i)) for i in range(8)]
        )

        cipher.add_output([(node_1, (i, i)) for i in range(8)])
        cipher.add_output([(node_2, (i, i+8)) for i in range(8)])

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(Toy4, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
