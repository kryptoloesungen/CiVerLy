from civerly.andrx import AndRX
from civerly.component import AND_CVL, XOR_CVL, RotateLayer_CVL, RoundkeyXOR_CVL

# Round: Add round constant → θ(key, state) → π1 → γ → π2
# θ (theta): linear diffusion + key injection (XORs + byte-rotations)
# π1, π2: word rotations (RX part)
# γ (gamma): the nonlinear layer (this is where AND + NOT appear)

#round constant rc1
rc1 = [0x80, 0x1B, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a]
RC_FINAL = 0xd4

class NOEKEON_CVL:
    def __init__(self, key=0x0, R=16, name=None):
        r"""
        EXAMPLES::

            sage: from civerly.cipher_implementations.noekeon import NOEKEON_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: cipher = NOEKEON_CVL() 
            sage: hex(vec_to_int(cipher(int_to_vec(0x04000e01000000f00a020000030c0d0, 128))))
            '0x759c49db3dea7e6896ba0a56575df255'

        TESTS::
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.noekeon import NOEKEON_CVL
            sage: P = 0x00000000000000000000000000000000
            sage: K = 0x00000000000000000000000000000000
            sage: C = 0xb1656851699e29fa24b70148503d2dfc
            sage: cipher = NOEKEON_CVL(key=K)
            sage: vec_to_int(cipher(int_to_vec(P, 128))) == C
            True

            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.noekeon import NOEKEON_CVL
            sage: K = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            sage: P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            sage: C = 0x2a78421b87c7d0924f26113f1d1349b2
            sage: cipher = NOEKEON_CVL(key=K)
            sage: vec_to_int(cipher(int_to_vec(P, 128))) == C
            True

            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.noekeon import NOEKEON_CVL
            sage: K = 0xb1656851699e29fa24b70148503d2dfc
            sage: P = 0x2a78421b87c7d0924f26113f1d1349b2
            sage: C = 0xe2f687e07b75660ffc372233bc47532c
            sage: cipher = NOEKEON_CVL(key=K)
            sage: vec_to_int(cipher(int_to_vec(P, 128))) == C
            True

        Models for differential cryptanalysis::

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.noekeon import NOEKEON_CVL
            sage: cipher = NOEKEON_CVL(R=1)
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     solve_range=(16, 20),
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            8096 variables and 16897 clauses were written to ...
            16

            sage: # optional - cadical # optional - espresso
            sage: from civerly.cipher_implementations.noekeon import NOEKEON_CVL
            sage: cipher = NOEKEON_CVL(R=1)
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CADICAL,
            ....:     solve_range=(16, 20),
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            8096 variables and 16897 clauses were written to ...
            16
            

        Models for linear cryptanalysis::

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.noekeon import NOEKEON_CVL
            sage: cipher = NOEKEON_CVL(R=1)
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     solve_range=(10, 20),
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            8096 variables and 17345 clauses were written to ...
            10

            sage: # optional - cadical # optional - espresso
            sage: from civerly.cipher_implementations.noekeon import NOEKEON_CVL
            sage: cipher = NOEKEON_CVL(R=1)
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CADICAL,
            ....:     solve_range=(10, 20),
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            8096 variables and 17345 clauses were written to ...
            10

        """
        if name is None:
            name = "Noekeon"
        assert 0 <= key < (1 << 128)
        assert 0 <= R <= 16

        #computing the subkeys based on the paper's specifications
        K0 = (key >> 96) & 0xFFFFFFFF
        K1 = (key >> 64) & 0xFFFFFFFF
        K2 = (key >> 32) & 0xFFFFFFFF
        K3 = key & 0xFFFFFFFF
        #xor operation
        xor = XOR_CVL(32, name="xor")
        #AND operation
        and1 = AND_CVL(32, name="and")
        #key addition
        not1 = RoundkeyXOR_CVL(32, 0xFFFFFFFF, name="not")
        #rotation operation
        rotL8 = RotateLayer_CVL(32, 8, name="rotl8")
        rotL24 = RotateLayer_CVL(32, 24, name="rotl24")
        #subkeys addition
        kx0 = RoundkeyXOR_CVL(32, K0, name="k0")
        kx1 = RoundkeyXOR_CVL(32, K1, name="k1")
        kx2 = RoundkeyXOR_CVL(32, K2, name="k2")
        kx3 = RoundkeyXOR_CVL(32, K3, name="k3")
        
        #THETA
        theta = AndRX(32, 4, 4, name="theta")
        #temp = a0 ^ a2
        t0 = theta.add_subcipher(xor, [(theta.IN, (0, 0)), (theta.IN, (2, 1))])
        #temp ^= ROTL8(temp) ^ ROTL24(temp)
        t0_r8 = theta.add_subcipher(rotL8, [(t0, (0, 0))])
        t0_r24 = theta.add_subcipher(rotL24, [(t0, (0, 0))])
        t1 = theta.add_subcipher(xor, [(t0, (0, 0)), (t0_r8, (0, 1))])
        t2 = theta.add_subcipher(xor, [(t1, (0, 0)), (t0_r24, (0, 1))])
        # a1 ^= t2
        a1 = theta.add_subcipher(xor, [(theta.IN, (1, 0)), (t2, (0, 1))])
        # a3 ^= t2
        a3 = theta.add_subcipher(xor, [(theta.IN, (3, 0)), (t2, (0, 1))])
        # key add
        a0k = theta.add_subcipher(kx0, [(theta.IN, (0, 0))])
        a1k = theta.add_subcipher(kx1, [(a1, (0, 0))])
        a2k = theta.add_subcipher(kx2, [(theta.IN, (2, 0))])
        a3k = theta.add_subcipher(kx3, [(a3, (0, 0))])
        # temp = a1k ^ a3k
        u0 = theta.add_subcipher(xor, [(a1k, (0, 0)), (a3k, (0, 1))])
        #temp ^= ROTL8(temp) ^ ROTL24(temp)
        u0_r8 = theta.add_subcipher(rotL8, [(u0, (0, 0))])
        u0_r24 = theta.add_subcipher(rotL24, [(u0, (0, 0))])
        u1 = theta.add_subcipher(xor, [(u0, (0, 0)), (u0_r8, (0, 1))])
        u2 = theta.add_subcipher(xor, [(u1, (0, 0)), (u0_r24, (0, 1))])
        # a0 ^= u2
        a0 = theta.add_subcipher(xor, [(a0k, (0, 0)), (u2, (0, 1))])
        # a2 ^= u2
        a2 = theta.add_subcipher(xor, [(a2k, (0, 0)), (u2, (0, 1))])

        theta.add_output([(a0, (0, 0)), (a1k, (0, 1)), (a2, (0, 2)), (a3k, (0, 3))])

        pi1 = AndRX(32, 4, 4, name="pi1")
        rot1 = RotateLayer_CVL(32, 1, name="rotl1")
        rot5 = RotateLayer_CVL(32, 5, name="rotl5")
        rot2 = RotateLayer_CVL(32, 2, name="rotl2")

        p1_a1 = pi1.add_subcipher(rot1, [(pi1.IN, (1, 0))])
        p1_a2 = pi1.add_subcipher(rot5, [(pi1.IN, (2, 0))])
        p1_a3 = pi1.add_subcipher(rot2, [(pi1.IN, (3, 0))])

        pi1.add_output([
            (pi1.IN, (0, 0)),
            (p1_a1, (0, 1)),
            (p1_a2, (0, 2)),
            (p1_a3, (0, 3)),
        ])

        pi2 = AndRX(32, 4, 4, name="pi2")
        rot31 = RotateLayer_CVL(32, 31, name="rotr1")
        rot27 = RotateLayer_CVL(32, 27, name="rotr5")
        rot30 = RotateLayer_CVL(32, 30, name="rotr2")

        p2_a1 = pi2.add_subcipher(rot31, [(pi2.IN, (1, 0))])
        p2_a2 = pi2.add_subcipher(rot27, [(pi2.IN, (2, 0))])
        p2_a3 = pi2.add_subcipher(rot30, [(pi2.IN, (3, 0))])

        pi2.add_output([
            (pi2.IN, (0, 0)),
            (p2_a1, (0, 1)),
            (p2_a2, (0, 2)),
            (p2_a3, (0, 3)),
        ])

        #GAMMA
        gamma = AndRX(32, 4, 4, name="gamma")
        # t = ~(a3|a2) = (~a3) & (~a2)
        na3_1 = gamma.add_subcipher(not1, [(gamma.IN, (3, 0))])
        na2_1 = gamma.add_subcipher(not1, [(gamma.IN, (2, 0))])
        t_or1 = gamma.add_subcipher(and1, [(na3_1, (0, 0)), (na2_1, (0, 1))])
        a1_1 = gamma.add_subcipher(xor, [(gamma.IN, (1, 0)), (t_or1, (0, 1))])
        # a0 ^= a2 & a1
        a2_and_a1_1 = gamma.add_subcipher(and1, [(gamma.IN, (2, 0)), (a1_1, (0, 1))])
        a0_1 = gamma.add_subcipher(xor, [(gamma.IN, (0, 0)), (a2_and_a1_1, (0, 1))])
        # After swap: a0 = old a3, a3 = a0_1, a1 = a1_1, a2 = old a2
        x01 = gamma.add_subcipher(xor, [(gamma.IN, (3, 0)), (a1_1, (0, 1))])  
        x012 = gamma.add_subcipher(xor, [(x01, (0, 0)), (a0_1, (0, 1))])    
        a2_1 = gamma.add_subcipher(xor, [(gamma.IN, (2, 0)), (x012, (0, 1))])    
        # second time: a1 ^= ~(a3 | a2) with updated a3=a0_1 and a2=a2_1
        na3_2 = gamma.add_subcipher(not1, [(a0_1, (0, 0))])  # ~a3
        na2_2 = gamma.add_subcipher(not1, [(a2_1, (0, 0))])  # ~a2
        t_or2 = gamma.add_subcipher(and1, [(na3_2, (0, 0)), (na2_2, (0, 1))])
        a1_2 = gamma.add_subcipher(xor, [(a1_1, (0, 0)), (t_or2, (0, 1))])
        # a0 ^= a2 & a1 
        a2_and_a1_2 = gamma.add_subcipher(and1, [(a2_1, (0, 0)), (a1_2, (0, 1))])
        a0_2 = gamma.add_subcipher(xor, [(gamma.IN, (3, 0)), (a2_and_a1_2, (0, 1))])  
        gamma.add_output([
            (a0_2, (0, 0)),
            (a1_2, (0, 1)),
            (a2_1, (0, 2)),
            (a0_1, (0, 3)),
        ])
        

        round_cipher = AndRX(32, 4, 4, name="noekeon_round")
        rc_xor = RoundkeyXOR_CVL(32, 0x0, name="rc")  # const set per round
        node_rc = round_cipher.add_subcipher(rc_xor, [(round_cipher.IN, (0, 0))])
        node_theta = round_cipher.add_subcipher(theta,[(node_rc, (0, 0)), (round_cipher.IN, (1, 1)), (round_cipher.IN, (2, 2)), (round_cipher.IN, (3, 3))])
        node_pi1 = round_cipher.add_subcipher(pi1,[(node_theta, (0, 0)), (node_theta, (1, 1)), (node_theta, (2, 2)), (node_theta, (3, 3))])
        node_gamma = round_cipher.add_subcipher(gamma,[(node_pi1, (0, 0)), (node_pi1, (1, 1)), (node_pi1, (2, 2)), (node_pi1, (3, 3))])
        node_pi2 = round_cipher.add_subcipher(pi2,[(node_gamma, (0, 0)), (node_gamma, (1, 1)), (node_gamma, (2, 2)), (node_gamma, (3, 3))])
        round_cipher.add_output([
            (node_pi2, (0, 0)),
            (node_pi2, (1, 1)),
            (node_pi2, (2, 2)),
            (node_pi2, (3, 3)),
        ])
        self._round_template = round_cipher
        self._node_rc = node_rc

        cipher = AndRX(32, 4, 4, name=name)
        node = cipher.IN
        for r in range(R):
            rc_word = (int(rc1[r]) & 0xFF) 
            round_cipher.nodes[node_rc].const = rc_word
            node = cipher.add_subcipher(round_cipher,[(node, (0, 0)), (node, (1, 1)), (node, (2, 2)), (node, (3, 3))])

        # finalization: a0 ^= (RC_FINAL<<24), then theta(key,state)
        final_node = node
        if R == 16:
            rc_final_xor = RoundkeyXOR_CVL(32, int(RC_FINAL) & 0xFF, name="rc_final")
            node_rcf = cipher.add_subcipher(rc_final_xor, [(node, (0, 0))])
            final_node = cipher.add_subcipher(theta,[(node_rcf, (0, 0)), (node, (1, 1)), (node, (2, 2)), (node, (3, 3))])

        cipher.add_output([
            (final_node, (0, 0)),
            (final_node, (1, 1)),
            (final_node, (2, 2)),
            (final_node, (3, 3)),
        ])
        self.noekeon_cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(NOEKEON_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.noekeon_cipher