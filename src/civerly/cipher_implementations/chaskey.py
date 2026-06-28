from civerly.addrx import AddRX
from civerly.component import RotateLayer_CVL, ModAdd_CVL, XOR_CVL

class ChaskeyQRF_CVL:
    #chaskey permutation function
    def __init__(self, name=None):
        r"""
        EXAMPLES::
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.chaskey import ChaskeyQRF_CVL
            sage: qrf = ChaskeyQRF_CVL()
            sage: hex(vec_to_int(qrf(int_to_vec(0x11111111_22222222_33333333_44444444, 128))))
            '0x6666666655555555eeeeeeee00000000'

        TESTS::
            sage: # optional - cryptominisat
            sage: from civerly.cipher_implementations.chaskey import ChaskeyQRF_CVL
            sage: from civerly.model_options import *
            sage: cipher = ChaskeyQRF_CVL()
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     solve_range=(0, 8),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            ....:   cipher.generate_report(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            2044 variables and 5213 clauses were written to ...
            0
            Output file in: ...

            sage: # optional - cadical
            sage: from civerly.cipher_implementations.chaskey import ChaskeyQRF_CVL
            sage: from civerly.model_options import *
            sage: cipher = ChaskeyQRF_CVL()
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sat_solver=SOLVER.CADICAL,
            ....:     solve_range=(0, 8),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            ....:   cipher.generate_report(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            2044 variables and 5213 clauses were written to ...
            0
            Output file in: ...

            sage: # optional - cryptominisat
            sage: from civerly.cipher_implementations.chaskey import ChaskeyQRF_CVL
            sage: from civerly.model_options import *
            sage: cipher = ChaskeyQRF_CVL()
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            2048 variables and 6053 clauses were written to ...
            0


        """
        if name is None:
            name = "ChaskeyQRF_CVL"
        chaskey_qr = AddRX(32, 4, 4, name=name)
        #modular addition operation
        add = ModAdd_CVL(32, name="add")
        #xor addition operation
        xor = XOR_CVL(32, name="xor")
        #rotation addition operation
        rot5 = RotateLayer_CVL(32, 5, name="rot5")
        rot7 = RotateLayer_CVL(32, 7, name="rot7")
        rot8 = RotateLayer_CVL(32, 8, name="rot8")
        rot13 = RotateLayer_CVL(32, 13, name="rot13")
        rot16 = RotateLayer_CVL(32, 16, name="rot16")

        # Step 1: v0 += v1
        a0 = chaskey_qr.add_subcipher(add, [(chaskey_qr.IN, (0, 0)), (chaskey_qr.IN, (1, 1))])
        # Step 2: v01 = rot5(v1)^v0
        b1 = chaskey_qr.add_subcipher(rot5, [(chaskey_qr.IN, (1, 0))])
        b2 = chaskey_qr.add_subcipher(xor, [(b1, (0, 0)), (a0, (0, 1))])
        a3 = chaskey_qr.add_subcipher(rot16, [(a0, (0, 0))])
        # Step 3: v2 += v3
        c0 = chaskey_qr.add_subcipher(add, [(chaskey_qr.IN, (2, 0)), (chaskey_qr.IN, (3, 1))])
        # Step 4: v3 = rot8(v3) ^ v2
        d1 = chaskey_qr.add_subcipher(rot8, [(chaskey_qr.IN, (3, 0))])
        d2 = chaskey_qr.add_subcipher(xor, [(d1, (0, 0)), (c0, (0,1))])
        # Step 5: v0 += v3
        a4 = chaskey_qr.add_subcipher(add, [(a3, (0, 0)), (d2, (0, 1))])
        d3 = chaskey_qr.add_subcipher(rot13, [(d2, (0, 0))])
        d4 = chaskey_qr.add_subcipher(xor, [(d3, (0, 0)), (a4, (0, 1))])
        # Step 6: v2 += v1
        c1 = chaskey_qr.add_subcipher(add, [(c0, (0, 0)), (b2, (0, 1))])
        b3 = chaskey_qr.add_subcipher(rot7, [(b2, (0, 0))])
        b4 = chaskey_qr.add_subcipher(xor, [(b3, (0, 0)), (c1, (0, 1))])
        c2 = chaskey_qr.add_subcipher(rot16, [(c1, (0, 0))])

        chaskey_qr.add_output([(a4, (0, 0)), (b4, (0, 1)), (c2, (0, 2)), (d4, (0, 3))])
        self.chaskey_qr = chaskey_qr

    def __new__(cls, *args, **kwargs):
        instance = super(ChaskeyQRF_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.chaskey_qr
    
class Chaskey_CVL:
    #this class applies the permutation function 8 times
    def __init__(self, R=8, name=None):
        r"""
        EXAMPLES::
            sage: input1 = (0x00000001_00000000_00000000_00000000)
            sage: input2 = (0x00112233_52ae30e8_89abcdef_13579bdf)
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.chaskey import Chaskey_CVL
            sage: chaskey_cipher = Chaskey_CVL(8)
            sage: hex(vec_to_int(chaskey_cipher(int_to_vec(input1, 128))))
            '0xf27c371c761fd76198743a8659d8bb11'
            sage: hex(vec_to_int(chaskey_cipher(int_to_vec(input2, 128))))
            '0xc0b67bbd97dc12bce4c26fdccf8223ec'

        TESTS::
            sage: # optional - cryptominisat
            sage: from civerly.cipher_implementations.chaskey import Chaskey_CVL
            sage: from civerly.model_options import *
            sage: chaskey_cipher = Chaskey_CVL(2)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     path=Path("./DOCTEST-Chaskey-Models/"))
            ....:   chaskey_cipher.analyse(model_options=model_options)
            4856 variables and 12217 clauses were written to ...
            4

        """
        if name is None:
            name = "Chaskey"
        
        chaskey_round = ChaskeyQRF_CVL()

        chaskey_cipher = AddRX(32, 4, 4, name=name)
        state = chaskey_cipher.IN
        for _ in range(R):
            state = chaskey_cipher.add_subcipher(chaskey_round, [(state, (i,i)) for i in range(4)])

        chaskey_cipher.add_output([(state, (i,i)) for i in range(4)])
        self.chaskey_cipher = chaskey_cipher

    def __new__(cls, *args, **kwargs):
        """Instantiate a Chaskey cipher."""
        instance = super(Chaskey_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.chaskey_cipher
