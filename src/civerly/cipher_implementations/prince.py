from sage.crypto.sboxes import PRINCE as prince_S
from sage.matrix.constructor import Matrix as matrix
from sage.matrix.special import block_matrix
from sage.rings.finite_rings.finite_field_constructor import GF

from civerly.cipher_implementations.base import CipherImplementation_CVL
from civerly.component import LinearLayer_CVL, RoundkeyXOR_CVL, SBox_CVL
from civerly.wordsboxcipher import WordSBoxCipher


def prince_m_hat(shift):
    r"""
    Return the :math:`16 \times 16` binary matrix of the PRINCE block
    :math:`\hat{M}^{(0)}` (``shift=0``) or :math:`\hat{M}^{(1)}` (``shift=1``)
    in the MSB-first bit order of :func:`civerly.util.int_to_vec`.

    Output nibble ``i`` is the XOR of the input nibbles ``j``, masked bitwise
    with ``0x7, 0xB, 0xD, 0xE`` rotated by ``i + j + shift``.
    """
    masks = (0x7, 0xB, 0xD, 0xE)
    blocks = [
        [
            matrix.diagonal(
                GF(2), [(masks[(i + j + shift) % 4] >> (3 - b)) & 1 for b in range(4)]
            )
            for j in range(4)
        ]
        for i in range(4)
    ]
    return block_matrix(GF(2), blocks, subdivide=False)


def _shift_rows(w):
    r"""
    Return the nibble that PRINCE's ShiftRows moves nibble ``w`` to.

    The state is a 4x4 array of nibbles stored column by column, so nibble
    ``w`` is in row ``w % 4``, and row ``r`` is rotated left by ``r`` columns.
    """
    return (w - 4 * (w % 4)) % 16


class PRINCE_CVL(CipherImplementation_CVL, WordSBoxCipher):
    def __init__(self, R=12, key_schedule=None, key=None, name="PRINCE"):
        r"""
        CiVerLy implementation of PRINCE (https://eprint.iacr.org/2012/529.pdf).
        It takes the following arguments:

            - ``R`` -- integer; Number of rounds (default: 12)

            - ``key_schedule`` -- :class:`civerly.keyschedule.KeySchedule`
              (optional); Key schedule instance used to derive round keys from
              ``key`` via :meth:`civerly.cipher.Cipher.set_round_keys`. No
              built-in key schedule is implemented for PRINCE; pass a custom
              ``KeySchedule`` subclass instance, or
              :class:`civerly.keyschedule.DefaultKeySchedule_CVL` to pass
              explicit round keys (see ``key``). The 12 round-key slots are, in
              order: the initial xor, the 5 forward rounds, the 5 backward
              rounds, and the final xor; only as many are consumed as needed
              for the given ``R``. Defaults to ``None`` (no key schedule,
              all-zero round keys).

            - ``key`` -- integer or list of integers (optional); The master
              key passed to ``key_schedule``, immediately expanded and injected via
              ``set_round_keys`` when both are given. Has no effect when
              ``key_schedule`` is ``None``.
              When using :class:`civerly.keyschedule.DefaultKeySchedule_CVL`,
              this is the list of round keys (round key 0 first).

            - ``name`` -- string; The name of the cipher (default: "PRINCE").
              This will be used to name the cipher and the corresponding file
              generated (such as the reports and cipher graphs).


        EXAMPLES::

            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.prince import PRINCE_CVL
            sage: prince_cipher = PRINCE_CVL(R=12)
            sage: hex(vec_to_int(prince_cipher(int_to_vec(0x0000000000000123, 64))))
            '0xb58040e6e141cb9a'

        TESTS::
            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: k = [
            ....:   0x0000000000000000, 0x13198a2e03707344, 0xa4093822299f31d0,
            ....:   0x082efa98ec4e6c89, 0x452821e638d01377, 0xbe5466cf34e90c6c,
            ....:   0x7ef84f78fd955cb1, 0x85840851f1ac43aa, 0xc882d32f25323c54,
            ....:   0x64a51195e0e3610d, 0xd3b5a399ca0c2399, 0xc0ac29b7c97c50dd
            ....: ]
            sage: from civerly.cipher_implementations.prince import PRINCE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: prince_cipher = PRINCE_CVL(R=12, key=k, key_schedule=DefaultKeySchedule_CVL(64, 12))
            sage: C = vec_to_int(prince_cipher(int_to_vec(0x0000000000000000, 64)))
            sage: print(hex(C))
            0x818665aa0d02dfda

            sage: k = [
            ....:   0x0000000000000000, 0x13198a2e03707344, 0xa4093822299f31d0,
            ....:   0x082efa98ec4e6c89, 0x452821e638d01377, 0xbe5466cf34e90c6c,
            ....:   0x7ef84f78fd955cb1, 0x85840851f1ac43aa, 0xc882d32f25323c54,
            ....:   0x64a51195e0e3610d, 0xd3b5a399ca0c2399, 0xc0ac29b7c97c50dd
            ....: ]
            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: from civerly.cipher_implementations.prince import PRINCE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: prince_cipher = PRINCE_CVL(R=12, key=k, key_schedule=DefaultKeySchedule_CVL(64, 12))
            sage: C = vec_to_int(prince_cipher(int_to_vec(0xFFFFFFFFFFFFFFFF, 64)))
            sage: print(hex(C))
            0x604ae6ca03c20ada

            # k = rks ^^ k1 (k1 in this test is 0x0), so rks = RC
            sage: k = [
            ....:   0x0000000000000000, 0x13198a2e03707344, 0xa4093822299f31d0,
            ....:   0x082efa98ec4e6c89, 0x452821e638d01377, 0xbe5466cf34e90c6c,
            ....:   0x7ef84f78fd955cb1, 0x85840851f1ac43aa, 0xc882d32f25323c54,
            ....:   0x64a51195e0e3610d, 0xd3b5a399ca0c2399, 0xc0ac29b7c97c50dd
            ....: ]
            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: from civerly.cipher_implementations.prince import PRINCE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: prince_cipher = PRINCE_CVL(R=12, key=k, key_schedule=DefaultKeySchedule_CVL(64, 12))
            sage: P  = 0x0000000000000000
            sage: k0 = 0xFFFFFFFFFFFFFFFF
            sage: k0_ = 0xFFFFFFFFFFFFFFFE
            sage: C_ = vec_to_int(prince_cipher(int_to_vec(P ^^ k0, 64)))
            sage: C =  C_ ^^ k0_
            sage: print(hex(C))
            0x9fb51935fc3df524

            # k = rks ^^ k1 (k1 in this test is 0xFFFFFFFFFFFFFFFF)
            # neglect k0 since k0=0x0
            sage: k = [
            ....:   0xffffffffffffffff, 0xece675d1fc8f8cbb, 0x5bf6c7ddd660ce2f,
            ....:   0xf7d1056713b19376, 0xbad7de19c72fec88, 0x41ab9930cb16f393,
            ....:   0x8107b087026aa34e, 0x7a7bf7ae0e53bc55, 0x377d2cd0dacdc3ab,
            ....:   0x9b5aee6a1f1c9ef2, 0x2c4a5c6635f3dc66, 0x3f53d6483683af22
            ....: ]
            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: from civerly.cipher_implementations.prince import PRINCE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: prince_cipher = PRINCE_CVL(R=12, key=k, key_schedule=DefaultKeySchedule_CVL(64, 12))
            sage: P  = 0x0000000000000000
            sage: C = vec_to_int(prince_cipher(int_to_vec(P, 64)))
            sage: print(hex(C))
            0x78a54cbe737bb7ef

            # k = rks ^^ k1 (k1 in this test is 0xfedcba9876543210)
            # neglect k0 since k0=0x0
            sage: k = [
            ....:   0xfedcba9876543210, 0xedc530b675244154, 0x5ad582ba5fcb03c0,
            ....:   0xf6f240009a1a5e99, 0xbbf49b7e4e842167, 0x4088dc5742bd3e7c,
            ....:   0x8024f5e08bc16ea1, 0x7b58b2c987f871ba, 0x365e69b753660e44,
            ....:   0x9a79ab0d96b7531d, 0x2d691901bc581189, 0x3e70932fbf2862cd
            ....: ]
            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: from civerly.cipher_implementations.prince import PRINCE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: prince_cipher = PRINCE_CVL(R=12, key=k, key_schedule=DefaultKeySchedule_CVL(64, 12))
            sage: P  = 0x0123456789abcdef
            sage: C = vec_to_int(prince_cipher(int_to_vec(P, 64)))
            sage: print(hex(C))
            0xae25ad3ca8fa9ccf


            sage: # optional - cryptominisat
            sage: from civerly.cipher_implementations.prince import PRINCE_CVL
            sage: from civerly.model_options import *
            sage: prince_cipher = PRINCE_CVL(R=4)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   prince_cipher.analyse(model_options)
            4112 variables and 12081 clauses were written to ...
            14

            sage: # optional - gurobi # optional - espresso
            sage: from civerly.cipher_implementations.prince \
            ....:   import PRINCE_CVL
            sage: from civerly.model_options import *
            sage: prince_cipher = PRINCE_CVL(R=2)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:     milp_solver=SOLVER.GUROBI,
            ....:     path=Path(tmpdir))
            ....:   prince_cipher.analyse(model_options)
            1840 variables and 1873 constraints were written to ...
            2

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.prince \
            ....:   import PRINCE_CVL
            sage: from civerly.model_options import *
            sage: prince_cipher = PRINCE_CVL(R=2)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   prince_cipher.analyse(model_options)
            1712 variables and 4641 clauses were written to ...
            1

        """
        super().__init__(4, 16, 16, R=R, key_schedule=key_schedule, key=key, name=name)

        # S-layer and the inverse S-layer
        sb = SBox_CVL(prince_S, name="SBox")
        sb_inv = SBox_CVL(prince_S.inverse(), name="SBoxInv")

        s_layer = WordSBoxCipher(4, 16, 16, name="SLayer")
        for j in range(16):
            n = s_layer.add_subcipher(sb, [(s_layer.IN, (j, 0))])
            s_layer.add_output([(n, (0, j))])

        s_layer_inv = WordSBoxCipher(4, 16, 16, name="SLayerInv")
        for j in range(16):
            n = s_layer_inv.add_subcipher(sb_inv, [(s_layer_inv.IN, (j, 0))])
            s_layer_inv.add_output([(n, (0, j))])

        # Linear layers. M' applies M^(0), M^(1), M^(1), M^(0) to the four
        # columns (nibbles 4c..4c+3). M = ShiftRows o M' and
        # M^{-1} = M' o ShiftRows^{-1}; ShiftRows is done by the wiring.
        m_hat = [
            LinearLayer_CVL(
                prince_m_hat(shift),
                branch_number_differential=4,
                branch_number_linear=4,
                name=f"M{shift}",
            )
            for shift in (0, 1)
        ]

        def add_m(cipher, src, shift_in=False, shift_out=False):
            # ``src[w]`` is the (node, word) feeding state nibble ``w``; returns
            # the same for the output of the linear layer.
            out = {}
            for c, shift in enumerate((0, 1, 1, 0)):
                words = range(4 * c, 4 * c + 4)
                edges = []
                for w in words:
                    node_in, word_in = src[_shift_rows(w) if shift_in else w]
                    edges.append((node_in, (word_in, w % 4)))
                node = cipher.add_subcipher(m_hat[shift], edges)
                for w in words:
                    out[_shift_rows(w) if shift_out else w] = (node, w % 4)
            return out

        def whole(node):
            return {i: (node, i) for i in range(16)}

        def edges_from(src):
            return [(n, (x, i)) for i, (n, x) in sorted(src.items())]

        # The round key addition layer
        xor_mask = RoundkeyXOR_CVL(64, 0x0, name="XOR")

        # Each forward round: S -> M -> XOR
        fwd_round = WordSBoxCipher(4, 16, 16, name="PRINCE_round_fwd")
        x = fwd_round.add_subcipher(s_layer, edges_from(whole(fwd_round.IN)))
        x = add_m(fwd_round, whole(x), shift_out=True)
        n_xor_fwd = fwd_round.add_subcipher(xor_mask, edges_from(x))
        fwd_round.add_output(edges_from(whole(n_xor_fwd)))

        # Middle round uses S -> M' -> S^{-1}
        mid_round = WordSBoxCipher(4, 16, 16, name="PRINCE_round_mid")
        x = mid_round.add_subcipher(s_layer, edges_from(whole(mid_round.IN)))
        x = add_m(mid_round, whole(x))
        x = mid_round.add_subcipher(s_layer_inv, edges_from(x))
        mid_round.add_output(edges_from(whole(x)))

        # Each backward round: XOR -> M^{-1} -> S^{-1}
        bwd_round = WordSBoxCipher(4, 16, 16, name="PRINCE_round_bwd")
        n_xor_bwd = bwd_round.add_subcipher(xor_mask, edges_from(whole(bwd_round.IN)))
        x = add_m(bwd_round, whole(n_xor_bwd), shift_in=True)
        x = bwd_round.add_subcipher(s_layer_inv, edges_from(x))
        bwd_round.add_output(edges_from(whole(x)))

        # PRINCE core
        st = self.IN
        _rk_components = []

        # initial add rks[0]
        if self.R >= 1:
            st = self.add_subcipher(xor_mask, [(st, (i, i)) for i in range(16)])
            _rk_components.append(self.nodes[st])

        # forward rounds r=1..5
        for _ in range(1, min(self.R, 6)):
            st = self.add_subcipher(fwd_round, [(st, (i, i)) for i in range(16)])
            _rk_components.append(self.nodes[st].nodes[n_xor_fwd])

        # middle round
        if self.R >= 6:
            st = self.add_subcipher(mid_round, [(st, (i, i)) for i in range(16)])

        # backward rounds r=6..10
        for _ in range(6, min(self.R, 11)):
            st = self.add_subcipher(bwd_round, [(st, (i, i)) for i in range(16)])
            _rk_components.append(self.nodes[st].nodes[n_xor_bwd])

        # final add rks[11]
        if self.R >= 12:
            st = self.add_subcipher(xor_mask, [(st, (i, i)) for i in range(16)])
            _rk_components.append(self.nodes[st])

        self.add_output([(st, (i, i)) for i in range(16)])
        self._rk_components = _rk_components

        if key_schedule is not None and key is not None:
            self.set_round_keys(key)
