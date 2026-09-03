from sage.crypto.sboxes import GIFT as gift_S

from civerly.component import PermuteLayer_CVL, RoundkeyXOR_CVL, SBox_CVL
from civerly.wordsboxcipher import WordSBoxCipher


class GIFT64_CVL:
    # Bit permutation specifications with LSB-indexing
    Perm_LSB = (
        0, 17, 34, 51, 48, 1, 18, 35, 32, 49, 2, 19, 16, 33, 50, 3,
        4, 21, 38, 55, 52, 5, 22, 39, 36, 53, 6, 23, 20, 37, 54, 7,
        8, 25, 42, 59, 56, 9, 26, 43, 40, 57, 10, 27, 24, 41, 58, 11,
        12, 29, 46, 63, 60, 13, 30, 47, 44, 61, 14, 31, 28, 45, 62, 15,
    )  # fmt: skip

    @staticmethod
    def lsb_to_msb(permutation_lsb):
        """
        Since this implementation is based on the C reference implementation, which uses LSB indexing,
        we have to convert it to MSB indexing to be compatible with the original paper.
        To this end, we reverse the indexing, where the bit index 0 would correspond
        to the MSB, instead of the LSB.
        """
        n = len(permutation_lsb)
        permutation_msb = [0] * n
        for i in range(n):
            permutation_msb[n - 1 - i] = (n - 1) - permutation_lsb[i]
        return permutation_msb

    def __init__(self, R=28, key_schedule=None, k=None, name="GIFT-64"):
        r"""
        Lightweight CiVerLy implementation of the GIFT-64 block cipher.

        This implementation models:
            - the substitution layer SubCells
            - the permutation layer PermBits
            - the round key addition AddRoundKey

        Takes the following arguments:

            - ``R`` -- integer; Number of rounds (default 28)

            - ``key_schedule`` -- :class:`civerly.keyschedule.KeySchedule`
              (optional); Key schedule instance used to derive round keys from
              ``k`` via ``set_round_keys``. No built-in key schedule is
              implemented for GIFT-64; pass a custom ``KeySchedule`` subclass
              instance, or :class:`civerly.keyschedule.DefaultKeySchedule_CVL`
              to pass explicit round keys (see ``k``). Defaults to ``None``
              (no key schedule, all-zero round keys).

            - ``k`` -- integer (optional); The master key passed to
              ``key_schedule``, immediately expanded and injected via
              ``set_round_keys`` when both are given. Has no effect when
              ``key_schedule`` is ``None``.

            - ``name`` -- string; The object's name (default "GIFT-64")


        EXAMPLES::
            sage: from civerly.cipher_implementations.gift import GIFT64_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: gift64 = GIFT64_CVL(R=28)
            sage: hex(vec_to_int(gift64(int_to_vec(0x0, 64))))
            '0x0'


        TESTS::

        Using test vectors from the original implementation
        (see files 'GIFT64_test_vector_1.txt', 'GIFT64_test_vector_2.txt'
        and 'GIFT64_test_vector_3.txt' in
        https://github.com/giftcipher/gift/blob/master/implementations/test%20vectors):

            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: k = 0x8000000000000008800000000000008880000000000008888000000000008888800000000008888880000000008888808000000000888808800000000088808880000000008808888000000000808888800000000008888080000000008888008000000000888008800000000088008880000000008008888000000000008880800000000008880880000000008880808000000000880808800000000080808880000000000808808000000000808800800000000008800080000000008800008000000000800008800000000000008080000000000008088000000000008088
            sage: from civerly.cipher_implementations.gift import GIFT64_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: gift64 = GIFT64_CVL(R=28, k=k, key_schedule=DefaultKeySchedule_CVL(64, 28))
            sage: vec_to_int(gift64(int_to_vec(0x0, 64))) == 0xf62bc3ef34f775ac
            True


            sage: k = 0x8233023002030208b2333230320332888233023002030a88b23332303203ba8880122203200a8a9b9032322330aa9ab380122203208a8a1b9032322330aa92bb8201022202b90a9ab201322232b1ba9a8201022202398a92b201322232b9ba1282020013229aa00b9222103332ba30ab820200132292288b922210333232b8a382130210022b8a28b213321032abb2a08213021002ab0a28b213321032a3b2a8a0120203000a2a93b032122310a2ba33a0120203000aa213b032122310aa3233822102020291023ab2213202321132b28221020202110a3ab22132023211b2ba
            sage: from civerly.cipher_implementations.gift import GIFT64_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: gift64 = GIFT64_CVL(R=28, k=k, key_schedule=DefaultKeySchedule_CVL(64, 28))
            sage: vec_to_int(gift64(int_to_vec(0xfedcba9876543210, 64))) == 0xc1b71f66160ff587
            True


            sage: k = 0xa300032213120119b13101123333319ba032033120232a99a13322132003999a81221112231b8b888330311113bbbbb18131220320b9aa3a8231222313b883999110231103aa0b8ab11331311193abbaa20120330238a9b380033132239ba81383110122018ab31ab3311331219813bba2330030239328a99310033122338aa18302010033188b3bb333211231b99193a032231120ab0a39a113001320a3b39aa3021310013b09828332333113b1b911a13122230039a2128231020113b82333933203130180230891133333311321b0822120332210293ba20331120113a0bb
            sage: from civerly.cipher_implementations.gift import GIFT64_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: gift64 = GIFT64_CVL(R=28, k=k, key_schedule=DefaultKeySchedule_CVL(64, 28))
            sage: vec_to_int(gift64(int_to_vec(0xc450c7727a9b8a7d, 64))) == 0xe3272885fa94ba8b
            True

        Model the cipher with MILP:

            sage: # optional - scip
            sage: from civerly.cipher_implementations.gift import GIFT64_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: gift64_cipher = GIFT64_CVL(R=2)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir))
            ....:   gift64_cipher.analyse(model_options)
            482 variables and 503 constraints were written to ...
            2

            sage: # optional - scip
            sage: from civerly.cipher_implementations.gift import GIFT64_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: gift64_cipher = GIFT64_CVL(R=2)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir))
            ....:   gift64_cipher.analyse(model_options)
            2048 variables and 2337 constraints were written to ...
            3.4150374993

            sage: # optional - scip
            sage: from civerly.cipher_implementations.gift import GIFT64_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: gift64_cipher = GIFT64_CVL(R=2)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   gift64_cipher.analyse(model_options)
            2048 variables and 3649 constraints were written to ...
            3.4150374993


            sage: # optional - gurobi
            sage: from civerly.cipher_implementations.gift import GIFT64_CVL
            sage: from civerly.model_options import *
            sage: gift64_cipher = GIFT64_CVL(R=4)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:     milp_solver=SOLVER.GUROBI,
            ....:     path=Path(tmpdir))
            ....:   gift64_cipher.analyse(model_options)
            ....:   gift64_cipher.generate_report(model_options)
            3712 variables and 4353 constraints were written to ...
            11.4150374993
            Output file in: ...


            sage: # optional - gurobi
            sage: from civerly.cipher_implementations.gift import GIFT64_CVL
            sage: from civerly.model_options import *
            sage: gift64_cipher = GIFT64_CVL(R=4)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=SOLVER.GUROBI,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   gift64_cipher.analyse(model_options)
            ....:   gift64_cipher.generate_report(model_options)
            3712 variables and 6977 constraints were written to ...
            11.4150374993
            Output file in: ...


        Model the cipher with SAT using different values for ``sat_precision``:

            sage: # optional - cryptominisat espresso
            sage: from civerly.cipher_implementations.gift import GIFT64_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: gift64_cipher = GIFT64_CVL(R=2)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   gift64_cipher.analyse(model_options)
            2048 variables and 5377 clauses were written to ...
            3

            sage: # optional - cryptominisat espresso
            sage: from civerly.cipher_implementations.gift import GIFT64_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: gift64_cipher = GIFT64_CVL(R=2)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     solve_range=(0, 10),
            ....:     sat_precision=1,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   gift64_cipher.analyse(model_options)
            2048 variables and 5377 clauses were written to ...
            3.4

            sage: # optional - cadical # optional - espresso
            sage: from civerly.cipher_implementations.gift import GIFT64_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: gift64_cipher = GIFT64_CVL(R=4)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CADICAL,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   gift64_cipher.analyse(model_options)
            ....:   trail = str(gift64_cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            3712 variables and 10113 clauses were written to ...
            11


        Linear cryptanalysis::

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.gift import GIFT64_CVL
            sage: from civerly.model_options import *
            sage: gift64_cipher = GIFT64_CVL(R=4)
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
            ....:   gift64_cipher.analyse(model_options)
            ....:   trail = str(gift64_cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            3648 variables and 8449 clauses were written to ...
            5

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.gift import GIFT64_CVL
            sage: from civerly.model_options import *
            sage: gift64_cipher = GIFT64_CVL(R=4)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   gift64_cipher.analyse(model_options)
            3648 variables and 8449 clauses were written to ...
            5

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.gift import GIFT64_CVL
            sage: from civerly.model_options import *
            sage: gift64_cipher = GIFT64_CVL(R=5)
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
            ....:   gift64_cipher.analyse(model_options)
            ....:   trail = str(gift64_cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            4464 variables and 10401 clauses were written to ...
            7

        """

        rks = [0] * R

        # SubCells
        # 16 4-bits S-boxes in parallel
        sbox = SBox_CVL(gift_S, name="GIFT64_SBox")
        subcells = WordSBoxCipher(4, 16, 16, name="SubCells")
        for i in range(16):
            node = subcells.add_subcipher(sbox, [(subcells.IN, (i, 0))])
            subcells.add_output([(node, (0, i))])

        # PermBits
        # First convert the permutation list from LSB to MSB, then perform the bitwise permutation
        perm_msb = self.lsb_to_msb(self.Perm_LSB)
        permbits = PermuteLayer_CVL(perm_msb, word_coarseness=1, name="PermBits64")

        # Implementation of the GIFT64 cipher
        gift = WordSBoxCipher(4, 16, 16, name=name)
        state = gift.IN

        rk_components = []
        for r in range(R):
            state = gift.add_subcipher(subcells, [(state, (i, i)) for i in range(16)])
            state = gift.add_subcipher(permbits, [(state, (i, i)) for i in range(16)])
            ark = RoundkeyXOR_CVL(64, const=rks[r], name=f"AddRoundKey_{r}")
            state = gift.add_subcipher(ark, [(state, (i, i)) for i in range(16)])
            rk_components.append(state)

        gift.add_output([(state, (i, i)) for i in range(16)])
        gift._rk_components = [gift.nodes[n] for n in rk_components]
        gift.key_schedule = key_schedule
        if key_schedule is not None and k is not None:
            gift.set_round_keys(k)
        self.gift_cipher = gift

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.gift_cipher


class GIFT128_CVL:
    # Bit permutation specifications with LSB-indexing
    Perm_LSB = (
        0, 33, 66, 99, 96, 1, 34, 67, 64, 97, 2, 35, 32, 65, 98, 3,
        4, 37, 70, 103, 100, 5, 38, 71, 68, 101, 6, 39, 36, 69, 102, 7,
        8, 41, 74, 107, 104, 9, 42, 75, 72, 105, 10, 43, 40, 73, 106, 11,
        12, 45, 78, 111, 108, 13, 46, 79, 76, 109, 14, 47, 44, 77, 110, 15,
        16, 49, 82, 115, 112, 17, 50, 83, 80, 113, 18, 51, 48, 81, 114, 19,
        20, 53, 86, 119, 116, 21, 54, 87, 84, 117, 22, 55, 52, 85, 118, 23,
        24, 57, 90, 123, 120, 25, 58, 91, 88, 121, 26, 59, 56, 89, 122, 27,
        28, 61, 94, 127, 124, 29, 62, 95, 92, 125, 30, 63, 60, 93, 126, 31,
    )  # fmt: skip

    @staticmethod
    def lsb_to_msb(permutation_lsb):
        """
        Since this implementation is based on the C reference implementation, which uses LSB indexing,
        we have to convert it to MSB indexing to be compatible with the original paper.
        To this end, we reverse the indexing, where the bit index 0 would correspond
        to the MSB, instead of the LSB.
        """
        n = len(permutation_lsb)
        permutation_msb = [0] * n
        for i in range(n):
            permutation_msb[n - 1 - i] = (n - 1) - permutation_lsb[i]
        return permutation_msb

    def __init__(self, R=40, key_schedule=None, k=None, name="GIFT-128"):
        r"""

        Lightweight CiVerLy implementation of the GIFT-64 block cipher.

        This implementation models:
            - the substitution layer SubCells
            - the permutation layer PermBits
            - the round key addition AddRoundKey

        Takes the following arguments:

            - ``R`` -- integer; Number of rounds (default 40)

            - ``key_schedule`` -- :class:`civerly.keyschedule.KeySchedule`
              (optional); Key schedule instance used to derive round keys from
              ``k`` via ``set_round_keys``. No built-in key schedule is
              implemented for GIFT-128; pass a custom ``KeySchedule`` subclass
              instance, or :class:`civerly.keyschedule.DefaultKeySchedule_CVL`
              to pass explicit round keys (see ``k``). Defaults to ``None``
              (no key schedule, all-zero round keys).

            - ``k`` -- integer (optional); The master key passed to
              ``key_schedule``, immediately expanded and injected via
              ``set_round_keys`` when both are given. Has no effect when
              ``key_schedule`` is ``None``.

            - ``name`` -- string; The object's name (default "GIFT-128")


        EXAMPLES::
            sage: from civerly.cipher_implementations.gift import GIFT128_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: gift128 = GIFT128_CVL(R=40)
            sage: hex(vec_to_int(gift128(int_to_vec(0x0, 128))))
            '0x99999999999999999999999999999999'

        TESTS::

        Using test vectors from the original implementation
        (see files 'GIFT128_test_vector_2.txt' and 'GIFT128_test_vector_3.txt' in
        https://github.com/giftcipher/gift/blob/master/implementations/test%20vectors):

            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: k = 0x86660660060606000066006000060008e6666660660666006066606060066088822646244206060400620024000208cca266666462462644606260246002e8cc800666066006060600600006000888ee8066666660660666606060066088e8e684022646244206060024000200cc886ac4226666646246266024600260cce0ea86000666066006060006000000ee08e8e6006666666066066006600060e6e8e8860402264624420600020044006a88a4a6442266666462466002604460eae82486060006660660060000006600e8800e86660066666660666000606660e8608e86060402264624420044006200a4088ac626442266666462604460626024e882860606000666066000660060000e8808e60666006666666060666060608ee080c20606040226462400620024008a084ce246264422666664606260246082e0cce00606060006660600600006000808e6e066066600666666606060066080e866a44206060402264600240002004c8062e4624626442266666024600260cc606286600606060006660006000000e60068e66066066600666660066000606660e0c624420606040226000200440062082ce664624626442266600260446062e0ace606600606060006000000660068088ee6666066066600666000606660e0e886a64624420606040200440062002c8802e6666462462644226044606260ace002866606600606060000660060008e0008e6666660660666006066606060866088822646244206060400620024000208c4a266666462462644606260246002e84c800666066006060600600006000880ee806666666066066660606006608868e684022646244206060024000200c4886ac42266666462462660246002604ce0e2
            sage: from civerly.cipher_implementations.gift import GIFT128_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: gift128 = GIFT128_CVL(R=40, k=k, key_schedule=DefaultKeySchedule_CVL(128, 40))
            sage: vec_to_int(gift128(int_to_vec(0xfedcba9876543210fedcba9876543210, 128))) \
            ....:   == 0x8422241a6dbf5a9346af468409ee0152
            True


            sage: k = 0xa666244600002020660620444462066ee40620024444042464002626602460cac2664662040000406202006626644eaee242044026220202664442426006e8a8a02666244600002020444462066eee8ea4640620024444042626602460caec80c0426646620400000066266446aeea0a82624204402622024242600660a8e6cca02026662446000044620666668e28cc8424640620024444602460426480aeae804042664662040026644626620a88e682026242044026226006602066ccca4280202026662446000666660620ccc46ac4042464062002446042640026ae60ac80004042664662044626620200e62eeca202026242044026602066444242e886800020202666244666062044446a8e6ec4440424640620026400262660ace0c284000040426646626202006626ec4e2ea622020262420440664442426086e0a8c60000202026662420444462066e6e8682444404246406202626602460c2ec00e20400004042664600662664462ee202c0262202026242044242600660a86644a446000020202666446206666686204ca00244440424640660246042640026a6c662040000404266266446266202086e8440262202026242600660206644c2cae62446000020202606666606204c4cea86200244440424646042640026a6e8a4e64662040000404246266202006eae64c2044026220202626020664442cae006a6662446000020206606204444ea066ee4062002444404246400262660a460cac2664662040000406202006626644ea6e242044026220202664442426006e828a02666244600002020444462066ee68ea4640620024444042626602460ca6c80c0426646620400000066266446a6ea0a8262420440262202424260066028e6c4
            sage: from civerly.cipher_implementations.gift import GIFT128_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: gift128 = GIFT128_CVL(R=40, k=k, key_schedule=DefaultKeySchedule_CVL(128, 40))
            sage: vec_to_int(gift128(int_to_vec(0xe39c141fa57dba43f08a85b6a91f86c1, 128))) == 0x13ede67cbdcc3dbf400a62d6977265ea
            True


        Model the cipher with MILP:

            sage: # optional - scip
            sage: from civerly.cipher_implementations.gift import GIFT128_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: gift128_cipher = GIFT128_CVL(R=4)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir))
            ....:   gift128_cipher.analyse(model_options)
            1732 variables and 1837 constraints were written to ...
            4

            sage: # optional - scip
            sage: from civerly.cipher_implementations.gift import GIFT128_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: gift128_cipher = GIFT128_CVL(R=2)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir))
            ....:   gift128_cipher.analyse(model_options)
            4096 variables and 4673 constraints were written to ...
            3.4150374993

            sage: # optional - scip
            sage: from civerly.cipher_implementations.gift import GIFT128_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: gift128_cipher = GIFT128_CVL(R=2)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   gift128_cipher.analyse(model_options)
            4096 variables and 7297 constraints were written to ...
            3.4150374993

            sage: # optional - gurobi
            sage: from civerly.cipher_implementations.gift import GIFT128_CVL
            sage: from civerly.model_options import *
            sage: gift128_cipher = GIFT128_CVL(R=2)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:     milp_solver=SOLVER.GUROBI,
            ....:     path=Path(tmpdir))
            ....:   gift128_cipher.analyse(model_options)
            ....:   gift128_cipher.generate_report(model_options)
            4096 variables and 4673 constraints were written to ...
            3.4150374993
            Output file in: ...

            sage: # optional - gurobi
            sage: from civerly.cipher_implementations.gift import GIFT128_CVL
            sage: from civerly.model_options import *
            sage: gift128_cipher = GIFT128_CVL(R=2)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=SOLVER.GUROBI,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   gift128_cipher.analyse(model_options)
            ....:   gift128_cipher.generate_report(model_options)
            4096 variables and 7297 constraints were written to ...
            3.4150374993
            Output file in: ...

        Model the cipher with SAT using different values for ``sat_precision``:

            sage: # optional - cryptominisat espresso
            sage: from civerly.cipher_implementations.gift import GIFT128_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: gift128_cipher = GIFT128_CVL(R=2)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   gift128_cipher.analyse(model_options)
            4096 variables and 10753 clauses were written to ...
            3


        Linear Cryptanalysis:

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.gift import GIFT128_CVL
            sage: from civerly.model_options import *
            sage: gift128_cipher = GIFT128_CVL(R=2)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   gift128_cipher.analyse(model_options)
            4032 variables and 9089 clauses were written to ...
            2

            """

        rks = [0] * R

        # SubCells
        # 32 4-bits S-boxes in parallel
        sbox = SBox_CVL(gift_S, name="GIFT128_SBox")
        subcells = WordSBoxCipher(4, 32, 32, name="SubCells")
        for i in range(32):
            node = subcells.add_subcipher(sbox, [(subcells.IN, (i, 0))])
            subcells.add_output([(node, (0, i))])

        # PermBits
        # First convert the permutation list from LSB to MSB, then perform the bitwise permutation
        perm_msb = self.lsb_to_msb(self.Perm_LSB)
        permbits = PermuteLayer_CVL(perm_msb, word_coarseness=1, name="PermBits128")

        # Implementation of the GIFT128 cipher
        gift = WordSBoxCipher(4, 32, 32, name=name)
        state = gift.IN

        rk_components = []
        for r in range(R):
            state = gift.add_subcipher(subcells, [(state, (i, i)) for i in range(32)])
            state = gift.add_subcipher(permbits, [(state, (i, i)) for i in range(32)])
            ark = RoundkeyXOR_CVL(128, const=rks[r], name=f"AddRoundKey_{r}")
            state = gift.add_subcipher(ark, [(state, (i, i)) for i in range(32)])
            rk_components.append(state)

        gift.add_output([(state, (i, i)) for i in range(32)])
        gift._rk_components = [gift.nodes[n] for n in rk_components]
        gift.key_schedule = key_schedule
        if key_schedule is not None and k is not None:
            gift.set_round_keys(k)
        self.gift_cipher = gift

    def __new__(cls, *args, **kwargs):
        """Instantiate a GIFT cipher."""
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.gift_cipher
