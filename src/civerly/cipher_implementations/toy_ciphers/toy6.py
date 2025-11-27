from civerly.cipher import Cipher
from civerly.component import ModAdd_CVL, RotateLayer_CVL


# cipher using ModAdd_CVL, enforcing probabilistic transition
class Toy6:
    def __init__(self):
        r"""

        TESTS::

            sage: from civerly.cipher_implementations.toy_ciphers.toy6 \
            ....:   import Toy6
            sage: from civerly.model_options import *
            sage: cipher = Toy6()
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   solver=SOLVER.CRYPTOMINISAT,
            ....:   path=Path("./DOCTEST-Toy6-Models/"))
            sage: # optional - cryptominisat
            sage: cipher.analyse(model_options)
            397 variables and 1142 clauses were written to
            'DOCTEST-Toy6-Models/Toy6.cnf'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : SAT
            [  0 ,  6] (trying w =   3) : SAT
            [  0 ,  3] (trying w =   1) : UNSAT
            [  2 ,  3] (trying w =   2) : SAT
            2
            sage: cipher.generate_report(model_options)
            Output file in: DOCTEST-Toy6-Models/Toy6.pdf
            sage: trail = str(cipher.get_trail(model_options))
            sage: assert "Unnamed Component" not in trail
            sage: import shutil
            sage: shutil.rmtree("DOCTEST-Toy6-Models", ignore_errors=True)


        """

        rot5 = RotateLayer_CVL(16, r=5, name="rot5")
        rot7 = RotateLayer_CVL(16, r=7, name="rot7")
        modadd = ModAdd_CVL(16, name="ModAdd")

        cipher = Cipher(32, 16, name="Toy6")

        node_rot1 = cipher.add_subcipher(rot5, [(cipher.IN, (i, i)) for i in range(16)])
        node_rot2 = cipher.add_subcipher(rot7, [(cipher.IN, (i + 16, i)) for i in range(16)])

        node_xor1 = cipher.add_subcipher(modadd, [(node_rot1, (i, i)) for i in range(16)] + [(cipher.IN, (i, i + 16)) for i in range(16)])
        node_xor2 = cipher.add_subcipher(modadd, [(node_rot2, (i, i)) for i in range(16)] + [(cipher.IN, (i + 16, i + 16)) for i in range(16)])

        node_modadd1 = cipher.add_subcipher(modadd, [(node_xor1, (i, i)) for i in range(16)] + [(node_xor2, (i, i + 16)) for i in range(16)])
        cipher.add_output([(node_modadd1, (i, i)) for i in range(16)])

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(Toy6, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
