from civerly.addrx import AddRX
from civerly.component import RotateLayer_CVL, ModAdd_CVL, XOR_CVL

class Salsa8QRF_CVL:
    #Salsa8 quarter round function
    def __init__(self, name=None):
        r"""
        EXAMPLES::
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.salsa8 import Salsa8QRF_CVL
            sage: qrf = Salsa8QRF_CVL()
            sage: hex(vec_to_int(qrf(int_to_vec(
            ....:   0x11111111_22222222_33333333_44444444, 
            ....: 128))))
            '0x44444444888888880000000055555555'

        TESTS::
            sage: from civerly.cipher_implementations.salsa8 import Salsa8QRF_CVL
            sage: from civerly.model_options import *
            sage: cipher = Salsa8QRF_CVL()
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   solver=SOLVER.CRYPTOMINISAT,
            ....:   solve_range=(0, 8),
            ....:   path=Path("./DOCTEST-SalsaQRF-Models/"))
            sage: # optional - cryptominisat
            sage: cipher.analyse(model_options=model_options)
            1916 variables and 4957 clauses were written to 'DOCTEST-SalsaQRF-Models/Salsa8-QRF.cnf'
            [  0 ,  8] (trying w =   4) : SAT
            [  0 ,  4] (trying w =   2) : SAT
            [  0 ,  2] (trying w =   1) : SAT
            [  0 ,  1] (trying w =   0) : SAT
            0
            sage: cipher.generate_report(model_options)
            Output file in: DOCTEST-SalsaQRF-Models/Salsa8-QRF.pdf
            sage: trail = str(cipher.get_trail(model_options))
            sage: assert "Unnamed Component" not in trail

            sage: from civerly.cipher_implementations.salsa8 import Salsa8QRF_CVL
            sage: from civerly.model_options import *
            sage: cipher = Salsa8QRF_CVL()
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   solver=SOLVER.CADICAL,
            ....:   solve_range=(0, 8),
            ....:   path=Path("./DOCTEST-SalsaQRF-Models/"))
            sage: # optional - cadical
            sage: cipher.analyse(model_options=model_options)
            1916 variables and 4957 clauses were written to 'DOCTEST-SalsaQRF-Models/Salsa8-QRF.cnf'
            [  0 ,  8] (trying w =   4) : SAT
            [  0 ,  4] (trying w =   2) : SAT
            [  0 ,  2] (trying w =   1) : SAT
            [  0 ,  1] (trying w =   0) : SAT
            0
            sage: cipher.generate_report(model_options)
            Output file in: DOCTEST-SalsaQRF-Models/Salsa8-QRF.pdf
            sage: trail = str(cipher.get_trail(model_options))
            sage: assert "Unnamed Component" not in trail

            sage: from civerly.cipher_implementations.salsa8 import Salsa8QRF_CVL
            sage: from civerly.model_options import *
            sage: cipher = Salsa8QRF_CVL()
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   solver=SOLVER.CRYPTOMINISAT,
            ....:   path=Path("./DOCTEST-SalsaQRF-Models/"))
            sage: # optional - cryptominisat
            sage: cipher.analyse(model_options=model_options)
            1920 variables and 5989 clauses were written to 'DOCTEST-SalsaQRF-Models/Salsa8-QRF.cnf'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : SAT
            [  0 ,  6] (trying w =   3) : SAT
            [  0 ,  3] (trying w =   1) : SAT
            [  0 ,  1] (trying w =   0) : SAT
            0

            sage: import shutil
            sage: shutil.rmtree("DOCTEST-SalsaQRF-Models", ignore_errors=True)
        """
        if name is None:
            name = "Salsa8-QRF"
        salsa_qr = AddRX(32, 4, 4, name=name)
        #modular addition operation
        add = ModAdd_CVL(32, name="add")
        #xor operation
        xor = XOR_CVL(32, name="xor")
        #rotate operation
        rot7 = RotateLayer_CVL(32, 7, name="rot7")
        rot9 = RotateLayer_CVL(32, 9, name="rot9")
        rot13 = RotateLayer_CVL(32, 13, name="rot13")
        rot18 = RotateLayer_CVL(32, 18, name="rot18")

        # Step 1: b ^= rotl(a + d, 7)
        t0 = salsa_qr.add_subcipher(add, [(salsa_qr.IN, (0, 0)), (salsa_qr.IN, (3, 1))])
        t1 = salsa_qr.add_subcipher(rot7, [(t0, (0, 0))])
        b1 = salsa_qr.add_subcipher(xor, [(salsa_qr.IN, (1, 0)), (t1, (0, 1))])
        # Step 2: c ^= rotl(b1 + a, 9)
        t2 = salsa_qr.add_subcipher(add, [(b1, (0, 0)), (salsa_qr.IN, (0, 1))])
        t3 = salsa_qr.add_subcipher(rot9, [(t2, (0, 0))])
        c1 = salsa_qr.add_subcipher(xor, [(salsa_qr.IN, (2, 0)), (t3, (0, 1))])
        # Step 3: d ^= rotl(c1 + b1, 13)
        t4 = salsa_qr.add_subcipher(add, [(c1, (0, 0)), (b1, (0, 1))])
        t5 = salsa_qr.add_subcipher(rot13, [(t4, (0, 0))])
        d1 = salsa_qr.add_subcipher(xor, [(salsa_qr.IN, (3, 0)), (t5, (0, 1))])
        # Step 4: a ^= rotl(d1 + c1, 18)
        t6 = salsa_qr.add_subcipher( add, [(d1, (0, 0)), (c1, (0, 1))])
        t7 = salsa_qr.add_subcipher(rot18, [(t6, (0, 0))])
        a1 = salsa_qr.add_subcipher(xor, [(salsa_qr.IN, (0, 0)), (t7, (0, 1))])

        salsa_qr.add_output([(a1, (0, 0)), (b1, (0, 1)), (c1, (0, 2)), (d1, (0, 3))])

        self.salsa_qr = salsa_qr

    def __new__(cls, *args, **kwargs):
        instance = super(Salsa8QRF_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.salsa_qr
    
class Salsa8_CVL:
    # Salsa8 stream generator
    def __init__(self, R=8, name=None):
        r"""
        EXAMPLES::
            sage: input1 = (0x61707865_04030201_08070605_0c0b0a09_100f0e0d_3320646e_01040103_06020905_00000007_00000000_79622d32_14131211_18171615_1c1b1a19_201f1e1d_6b206574)
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.salsa8 import Salsa8_CVL
            sage: salsa_cipher = Salsa8_CVL(2)
            sage: hex(vec_to_int(salsa_cipher(int_to_vec(input1, 512))))
            '0xba2409b11b7cce6a29115dcf5037e02737b75378348d94c83ea582b3c3a9a148825bfcb9226ae9eb63dd77487129a2154effd1ec5f25dc72a6c3d164152a26d8'

            sage: input2 = (0xa3b1c2d3_00112233_52ae30e8_89abcdef_13579bdf_2468ace0_0badc0de_cafef00d_11111111_22222222_33333333_44444444_55555555_66666666_77777777_88888888)
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.salsa8 import Salsa8_CVL
            sage: salsa_cipher = Salsa8_CVL(2)
            sage: hex(vec_to_int(salsa_cipher(int_to_vec(input2, 512))))
            '0x41b1b31d1296df111676ee175668aea816ef51124f730621d8d14d921cbae414f95dea20d4c516f4bfe236aaf0c865e5b016204d5e17a39dbf703e2d89b4363a'

        TESTS::
            sage: from civerly.cipher_implementations.salsa8 import Salsa8_CVL
            sage: from civerly.model_options import *
            sage: salsa = Salsa8_CVL(2)
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   solver=SOLVER.CRYPTOMINISAT,
            ....:   path=Path("./DOCTEST-Salsa-Models/"))
            sage: # optional - cryptominisat
            sage: salsa.salsa_cipher.analyse(model_options=model_options)
            24544 variables and 59105 clauses were written to 'DOCTEST-Salsa-Models/Salsa8.cnf'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : SAT
            [  0 ,  6] (trying w =   3) : SAT
            [  0 ,  3] (trying w =   1) : SAT
            [  0 ,  1] (trying w =   0) : SAT
            0

            sage: from civerly.cipher_implementations.salsa8 import Salsa8_CVL
            sage: from civerly.model_options import *
            sage: salsa = Salsa8_CVL(2)
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   solver=SOLVER.CRYPTOMINISAT,
            ....:   path=Path("./DOCTEST-Salsa-Models/"))
            sage: # optional - cryptominisat
            sage: salsa.salsa_cipher.analyse(model_options=model_options)
            24576 variables and 67361 clauses were written to 'DOCTEST-Salsa-Models/Salsa8.cnf'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : SAT
            [  0 ,  6] (trying w =   3) : SAT
            [  0 ,  3] (trying w =   1) : SAT
            [  0 ,  1] (trying w =   0) : UNSAT
            1

            sage: import shutil
            sage: shutil.rmtree("DOCTEST-Salsa-Models", ignore_errors=True)
        """
        if name is None:
            name = "Salsa8"
        
        salsa_qr = Salsa8QRF_CVL()

        salsa_cipher = AddRX(32, 16, 16, name=name)
        state = salsa_cipher.IN

        # apply the round function 4 times
        def apply_round(round_name, tuples, in_node):
            rounds=AddRX(32, 16, 16, name=round_name)
            out = {}
            for(a, b, c, d) in tuples:
                out_node = rounds.add_subcipher(
                    salsa_qr,
                    [
                        (rounds.IN, (a, 0)),
                        (rounds.IN, (b, 1)),
                        (rounds.IN, (c, 2)),
                        (rounds.IN, (d, 3)),
                    ],
                )
                out[a] = (out_node, 0)
                out[b] = (out_node, 1)
                out[c] = (out_node, 2)
                out[d] = (out_node, 3)
            
            rounds.add_output([(out[i][0], (out[i][1], i)) for i in range(16)])
            return salsa_cipher.add_subcipher(rounds, [(in_node, (i,i)) for i in range(16)])
        
        column_tuples = [
            (0, 4, 8, 12),
            (5, 9, 13, 1),
            (10, 14, 2, 6),
            (15, 3, 7, 11),
        ]
        row_tuples = [
            (0, 1, 2, 3),
            (5, 6, 7, 4),
            (10, 11, 8, 9),
            (15, 12, 13, 14),
        ]
        # apply the function in each round either row-wise or column-wise
        # for odd rounds, the round function is applied column-wise
        # otherwise, the round function is applied row-wise
        for r in range(R):
            if r%2 == 0:
                state = apply_round(f"column_round_{r+1}", column_tuples, state)
            else:
                state = apply_round(f"row_round_{r+1}", row_tuples, state)
        
        salsa_cipher.add_output([(state, (i,i)) for i in range(16)])
        self.salsa_cipher = salsa_cipher
   
    def __call__(self, state):
        return self.salsa_cipher(state)

