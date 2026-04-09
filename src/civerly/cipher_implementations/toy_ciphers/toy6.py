from civerly.cipher import Cipher
from civerly.component import ModAdd_CVL, RotateLayer_CVL


# cipher using ModAdd_CVL, enforcing probabilistic transition
class Toy6:
    def __init__(self):
        r"""

        TESTS::

            sage: # optional - cryptominisat
            sage: from civerly.cipher_implementations.toy_ciphers.toy6 \
            ....:   import Toy6
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy6()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       sat_solver=CRYPTOMINISAT_CVL(),
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            ....:   cipher.generate_report(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            397 variables and 1142 clauses were written to '...'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : SAT
            [  0 ,  6] (trying w =   3) : SAT
            [  0 ,  3] (trying w =   1) : UNSAT
            [  2 ,  3] (trying w =   2) : SAT
            2
            Output file in: ...


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
