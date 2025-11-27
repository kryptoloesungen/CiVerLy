from sage.matrix.constructor import Matrix as matrix
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.crypto.sbox import SBox
from civerly.sboxcipher import SBoxCipher
from civerly.component import LinearLayer_CVL
from civerly.component import SBox_CVL


# cipher testing whether linear modeling of k-branching works for k > 2
class Toy11:
    def __init__(self):
        r"""

        TESTS::

            sage: from civerly.cipher_implementations.toy_ciphers.toy11 \
            ....:   import Toy11
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: cipher = Toy11()
            sage: model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     solver=SOLVER.GUROBI,
            ....:     path=Path("./DOCTEST-Toy11-Models/")
            ....: )
            sage: cipher.analyse(model_options) # optional - gurobi # optional - espresso
            101 variables and 388 constraints were written to
            'DOCTEST-Toy11-Models/toy11.mps'
            1

            sage: # optional - cadical # optional - espresso
            sage: from civerly.cipher_implementations.toy_ciphers.toy11 \
            ....:   import Toy11
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: cipher = Toy11()
            sage: model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     solver=SOLVER.CADICAL,
            ....:     path=Path("./DOCTEST-Toy11-Models/")
            ....: )
            sage: cipher.analyse(model_options)
            89 variables and 436 clauses were written to
            'DOCTEST-Toy11-Models/toy11.cnf'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : SAT
            [  0 ,  6] (trying w =   3) : SAT
            [  0 ,  3] (trying w =   1) : SAT
            [  0 ,  1] (trying w =   0) : UNSAT
            1

            sage: import shutil
            sage: shutil.rmtree("DOCTEST-Toy11-Models", ignore_errors=True)

        """

        cipher = SBoxCipher(3, 8, name="toy11")
        arr = [
            [0, 1, 1],
            [1, 0, 1],
            [0, 0, 1]
        ]

        mat = matrix(GF(2), arr)
        ll = LinearLayer_CVL(mat, name="L")

        node = []
        node.append(cipher.add_subcipher(
            ll, [(cipher.IN, (i, i)) for i in range(3)]
        ))
        node.append(cipher.add_subcipher(
            ll, [(cipher.IN, (i, i)) for i in range(3)]
        ))
        node.append(cipher.add_subcipher(
            ll, [(cipher.IN, (i, i)) for i in range(3)]
        ))
        node.append(cipher.add_subcipher(
            ll, [(cipher.IN, (i, i)) for i in range(3)]
        ))

        S = SBox((
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
            0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
            4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
            15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
        ))
        sb = SBox_CVL(S, name="S")
        node2 = cipher.add_subcipher(
            sb,
            [(node[i // 3], (i % 3, i)) for i in range(6)]
        )

        S = SBox((
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
            0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
            4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
            15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 14
        ))
        sb = SBox_CVL(S, name="S")

        node3 = cipher.add_subcipher(
            sb,
            [
                (node[2], (0, 0)),
                (node[2], (1, 1)),
                (node[2], (2, 2)),
                (node[3], (0, 3)),
                (node[3], (1, 4)),
                (node[3], (2, 5))
            ]
        )
        cipher.add_output(
            [(node2, (i, i)) for i in range(4)]
        )
        cipher.add_output(
            [(node3, (i, i + 4)) for i in range(4)]
        )

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(Toy11, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
