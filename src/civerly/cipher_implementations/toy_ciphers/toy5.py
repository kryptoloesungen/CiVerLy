from civerly.sboxcipher import SBoxCipher
from civerly.cipher_implementations.toy_ciphers.toy3 import Toy3
from civerly.cipher_implementations.toy_ciphers.toy4 import Toy4


# cipher using cascade of toy3 and toy4
class Toy5:
    def __init__(self):
        r"""

        TESTS::

            sage: # optional - cadical # optional - espresso
            sage: from civerly.cipher_implementations.toy_ciphers.toy5 \
            ....:   import Toy5
            sage: from civerly.model_options import *
            sage: cipher = Toy5()
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:   sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:   sat_solver=CADICAL_CVL(),
            ....:   logic_minimizer=ESPRESSO_CVL(),
            ....:   path=Path("./DOCTEST-Toy5-Models/"))
            sage: cipher.analyse(model_options)
            2940 variables and 13997 clauses were written to
            'DOCTEST-Toy5-Models/Toy5.cnf'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : UNSAT
            [  7 , 12] (trying w =   9) : SAT
            [  7 ,  9] (trying w =   8) : SAT
            [  7 ,  8] (trying w =   7) : UNSAT
            8
            sage: cipher.generate_report(model_options)
            Output file in: DOCTEST-Toy5-Models/Toy5.pdf
            sage: trail = str(cipher.get_trail(model_options))
            sage: assert "Unnamed Component" not in trail

            sage: # optional - cadical # optional - espresso
            sage: from civerly.cipher_implementations.toy_ciphers.toy5 \
            ....:   import Toy5
            sage: from civerly.model_options import *
            sage: cipher = Toy5()
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:   sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:   sat_solver=CADICAL_CVL(),
            ....:   logic_minimizer=ESPRESSO_CVL(),
            ....:   path=Path("./DOCTEST-Toy5-Models/"))
            sage: cipher.analyse(model_options)
            Using existing file DOCTEST-Toy5-Models/espresso-5a255793_out.pla,
            make sure it is up to date!
            3256 variables and 11381 clauses were written to
            'DOCTEST-Toy5-Models/Toy5.cnf'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : UNSAT
            [  7 , 12] (trying w =   9) : SAT
            [  7 ,  9] (trying w =   8) : SAT
            [  7 ,  8] (trying w =   7) : UNSAT
            8
            sage: cipher.generate_report(model_options)
            Output file in: DOCTEST-Toy5-Models/Toy5.pdf
            sage: trail = str(cipher.get_trail(model_options))
            sage: assert "Unnamed Component" not in trail

            sage: # optional - gurobi
            sage: from civerly.cipher_implementations.toy_ciphers.toy5 \
            ....:   import Toy5
            sage: from civerly.model_options import *
            sage: cipher = Toy5()
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.MILP,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:   sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:   milp_solver=GUROBI_CVL(),
            ....:   path=Path("./DOCTEST-Toy5-Models/"))
            sage: cipher.analyse(model_options)
            3404 variables and 4177 constraints were written to
            'DOCTEST-Toy5-Models/Toy5.mps'
            8
            sage: cipher.generate_report(model_options)
            Output file in: DOCTEST-Toy5-Models/Toy5.pdf
            sage: trail = str(cipher.get_trail(model_options))
            sage: assert "Unnamed Component" not in trail
            sage: import shutil
            sage: shutil.rmtree("DOCTEST-Toy5-Models", ignore_errors=True)

        """
        cipher = SBoxCipher(48, 16, name="Toy5")

        toy3 = Toy3()
        toy4 = Toy4()

        node1 = cipher.add_subcipher(
            toy3, [(cipher.IN, (i, 31 - i)) for i in range(32)]
        )
        node2 = cipher.add_subcipher(
            toy3, [(cipher.IN, (i + 16, 31 - i)) for i in range(32)]
        )
        node3 = cipher.add_subcipher(
            toy4,
            [(node1, (i, i)) for i in range(16)] +
            [(node2, (i, i + 16)) for i in range(16)]
        )
        node4 = cipher.add_subcipher(
            toy4,
            [(node1, (i + 16, i)) for i in range(16)] +
            [(node2, (i + 16, i + 16)) for i in range(16)]
        )
        node5 = cipher.add_subcipher(
            toy4,
            [(node3, (i, (3*i) % 16)) for i in range(16)] +
            [(cipher.IN, (i + 32, ((5*i) % 16) + 16)) for i in range(16)]
        )

        node = cipher.add_subcipher(
            toy4,
            [(node4, (i, (i + 3) % 16)) for i in range(16)] +
            [(node5, (i, i + 16)) for i in range(16)]
        )

        cipher.add_output([(node, (i, i)) for i in range(16)])

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(Toy5, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
