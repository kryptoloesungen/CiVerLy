"""
CiVerLy implementation of the Qalqan block cipher.

Specification (reconstructed from the CPITS-II-2021 paper
"About Cryptographic Properties of the Qalqan Encryption Algorithm"
and the reference implementation in ``documentation/qalqan.py``):

    * Block size       : 128 bit
    * Key size         : 256 .. 1024 bit, in 128 bit steps
    * Number of rounds : N = 17 + floor((KLen - 256) / 128) * 2  (17 .. 29)

Structure of the round function (per the paper's XSL / LSX design):

    * ``S``  : byte-wise 8-bit S-box applied to all 16 bytes
    * ``L``  : byte-wise modular (mod 256) linear diffusion layer
    * ``K``  : round-key addition (mod 2^128) for the middle rounds,
               modulo-2 (XOR) key whitening for the first and last round

Encryption (matching ``documentation/qalqan.py::encrypt_block``)::

    state = K_start_xor(plaintext)                    # round key 0, XOR
    state = S(state)
    state = L(state)
    for rk in round_keys[1:N]:                        # N-1 middle rounds
        state = state + rk   (mod 2**128)
        state = S(state)
        state = L(state)
    state = K_fin_xor(state)                          # round key N, XOR

The nominal round count is *N* (17..29).  Because the first round uses
XOR whitening and the last round is also XOR whitening, the key schedule
must yield **N + 1** round keys.

**Rounds**
The rounds are numbered from ``0``:

* Round ``0``            : ``XOR(rk[0]) -> S -> L``   (initial whitening)
* Round ``i`` (1..N-1)   : ``ADD(rk[i]) -> S -> L``   (middle rounds)
* Round ``N``            : ``XOR(rk[N])``           (final whitening)

The constructor parameter ``R`` requests a cipher consisting of the first
``R`` rounds (rounds ``0, ..., R-1``); the full cipher has ``R = N + 1``
rounds and ends with the final whitening XOR, a reduced cipher ends with a
middle round ``ADD -> S -> L``.  ``N`` is determined by the ``key_size``
parameter (default: 256 bit, i.e. ``N = 17``).

Modeling notes
--------------
Qalqan mixes an S-box with modular addition, so it does not fit
``SBoxCipher``/``WordSBoxCipher`` (which reject ``ModAdd_CVL``) nor
``AddRX`` (which reject ``SBox_CVL``).  The general :class:`civerly.cipher.Cipher`
container is therefore used; it supports any component but only SAT modeling
(MILP is not available for ``Cipher``).

The diffusion layer ``L`` is *not* GF(2)-linear (it uses mod-256 addition),
so it is modeled as a dedicated subcipher built from ``ModAdd_CVL(8)"
components.  The 128-bit round-key addition is modeled with ``ModAdd_CVL(128)``
after reversing the bit order of the state (the reference uses little-endian
128-bit addition, while CiVerLy interprets a 128-bit vector big-endian).
"""

from sage.crypto.sbox import SBox

from civerly.cipher import Cipher
from civerly.cipher_implementations.base import CipherImplementation_CVL
from civerly.component import (
    C_CVL,
    RK_CVL,
    ModAdd_CVL,
    PermuteLayer_CVL,
    RoundkeyXOR_CVL,
    SBox_CVL,
)
from civerly.keyschedule import KeySchedule

# ---------------------------------------------------------------------------
# Qalqan S-box (Figure 1 in the paper / ``documentation/qalqan.py::SBOX``)
# ---------------------------------------------------------------------------

SBOX = (
    0xEB,
    0x89,
    0xDB,
    0xCB,
    0xF3,
    0xF5,
    0xFB,
    0x90,
    0xE6,
    0x3D,
    0xE5,
    0x2E,
    0xE3,
    0x0B,
    0x56,
    0xE1,
    0x6C,
    0x12,
    0x80,
    0x28,
    0xED,
    0x22,
    0x09,
    0x4A,
    0xEE,
    0x27,
    0x9B,
    0x58,
    0x35,
    0x57,
    0xEF,
    0x94,
    0x29,
    0xC0,
    0x16,
    0x7C,
    0x5E,
    0x87,
    0x0A,
    0x7E,
    0xE8,
    0x11,
    0x0E,
    0xAF,
    0x9A,
    0x84,
    0x3A,
    0x1A,
    0x69,
    0x71,
    0x8C,
    0xBC,
    0xD2,
    0x55,
    0x33,
    0xD1,
    0x85,
    0x75,
    0xB5,
    0x83,
    0xE9,
    0x50,
    0x54,
    0xAC,
    0x8A,
    0xD6,
    0x7F,
    0x1F,
    0x14,
    0x4E,
    0x21,
    0x82,
    0x30,
    0x24,
    0xDD,
    0x9F,
    0x1B,
    0x32,
    0x20,
    0xA8,
    0x6A,
    0xB0,
    0x97,
    0x62,
    0x19,
    0xD8,
    0xC8,
    0x0C,
    0x52,
    0x02,
    0x5C,
    0x43,
    0x03,
    0x95,
    0x13,
    0x81,
    0xAB,
    0x77,
    0xA6,
    0xF2,
    0x59,
    0x67,
    0x41,
    0xEC,
    0x76,
    0x98,
    0xB4,
    0x73,
    0x86,
    0x9C,
    0xF7,
    0xCF,
    0xDC,
    0xBA,
    0xA4,
    0xFD,
    0xC4,
    0x99,
    0xDF,
    0xCE,
    0xEA,
    0x1C,
    0x36,
    0xBD,
    0x34,
    0xD7,
    0x49,
    0x64,
    0x5A,
    0x6F,
    0x74,
    0x01,
    0xA0,
    0x39,
    0x91,
    0x00,
    0x15,
    0x3F,
    0x38,
    0xB8,
    0x8F,
    0x26,
    0x5F,
    0xF8,
    0x07,
    0xA3,
    0x0D,
    0xDA,
    0xF0,
    0xE7,
    0xD0,
    0xD9,
    0x93,
    0xF6,
    0x06,
    0x47,
    0x0F,
    0xA1,
    0x4B,
    0xC5,
    0x2A,
    0xFF,
    0x46,
    0x60,
    0xD5,
    0x1D,
    0x2F,
    0xA9,
    0x92,
    0x17,
    0x72,
    0x8E,
    0x7A,
    0xAA,
    0x18,
    0x6E,
    0x37,
    0x08,
    0x1E,
    0x63,
    0x31,
    0xC2,
    0xBF,
    0xC6,
    0x9E,
    0x65,
    0xD4,
    0x3B,
    0x96,
    0x9D,
    0xDE,
    0x45,
    0xCA,
    0x2D,
    0xA5,
    0xFE,
    0x4D,
    0xB9,
    0x66,
    0xC3,
    0xB3,
    0xCC,
    0xAD,
    0x61,
    0xBE,
    0x7B,
    0x68,
    0x88,
    0x25,
    0x2B,
    0x53,
    0x5B,
    0x44,
    0x40,
    0xA7,
    0xA2,
    0x5D,
    0xC9,
    0x51,
    0xAE,
    0xE4,
    0xC7,
    0xF9,
    0x78,
    0x70,
    0xCD,
    0x42,
    0x4F,
    0x4C,
    0x3C,
    0xE0,
    0x3E,
    0x7D,
    0xB7,
    0xD3,
    0xB2,
    0xF1,
    0x8D,
    0x79,
    0x8B,
    0x6B,
    0xE2,
    0x10,
    0x23,
    0x04,
    0x6D,
    0xC1,
    0xFC,
    0x05,
    0xB6,
    0xF4,
    0x48,
    0xBB,
    0xB1,
    0x2C,
    0xFA,
)


def _byte_rev_int(x):
    r"""
    Reverse the *byte* order of a 128-bit integer.

    CiVerLy interprets a 128-bit vector as big-endian with the bytes in their
    natural order, whereas the Qalqan reference implementation performs the
    128-bit round-key addition as a little-endian addition (byte order
    reversed, within-byte bit order preserved).  Reversing the byte order
    before and after a ``ModAdd_CVL(128)`` therefore realizes the
    little-endian addition on the natural (byte-wise) state layout used by the
    S-box and ``L`` layers.
    """
    return int.from_bytes(x.to_bytes(16, "big"), "little")


def _rounds_for_key(key_len):
    r"""
    Return ``N = 17 + floor((KLen - 256) / 128) * 2`` for a key of ``key_len``
    bytes.
    """
    bits = key_len * 8
    return 17 + ((bits - 256) // 128) * 2


def qalqan_round_keys_to_components(round_keys, key_size=256):
    r"""
    Convert Qalqan round keys from the reference representation into the
    representation stored in the round-key components of :class:`QALQAN_CVL`.

    The middle rounds ``1, ..., N-1`` add their round key modulo ``2^128``
    in little-endian byte order. :class:`QALQAN_CVL` realizes this by
    reversing the byte order of the state around a big-endian
    ``ModAdd_CVL(128)``, so the round keys of these rounds are stored with
    their byte order reversed. The whitening keys of rounds ``0`` and ``N``
    are XORed and stay unchanged.

    INPUT:

        - ``round_keys`` -- list of 128-bit integers; Reference round keys
          (big-endian integers of the 16 round-key bytes), in round order
          (round key of round ``0`` first).

        - ``key_size`` -- integer (default: ``256``); Key size in bits, which
          determines the number of rounds ``N``.

    OUTPUT: A list of 128-bit integers, in the same order as ``round_keys``.

    EXAMPLES::

        sage: from civerly.cipher_implementations.qalqan import (
        ....:   qalqan_round_keys_to_components)
        sage: rks = [0x0102, 0x0102, 0x0102]
        sage: [hex(k) for k in qalqan_round_keys_to_components(rks)]
        ['0x102',
         '0x2010000000000000000000000000000',
         '0x2010000000000000000000000000000']
        sage: rks = [0x0102] * 18
        sage: [hex(k) for k in qalqan_round_keys_to_components(rks)[-2:]]
        ['0x2010000000000000000000000000000', '0x102']
    """
    n = _rounds_for_key(key_size // 8)
    return [_byte_rev_int(rk) if 0 < r < n else rk for r, rk in enumerate(round_keys)]


class QALQAN_CVL(CipherImplementation_CVL, Cipher):
    def __init__(
        self,
        R=None,
        key_schedule=None,
        key=None,
        key_size=256,
        name="QALQAN",
    ):
        r"""
        The CiVerLy implementation of the Qalqan block cipher.
        Note that due to limited literature on Qalqan, the test vectors
        are obtained from a manually written reference implementation.

        The rounds are numbered ``0, ..., N``, where ``N`` is the nominal
        number of rounds for the key size (``17 + floor((KLen-256)/128)*2``):
        round ``0`` is ``XOR -> S -> L``, rounds ``1, ..., N-1`` are
        ``ADD -> S -> L`` and round ``N`` is the final whitening ``XOR``.
        Every round uses one 128-bit round key.

        INPUT:

            - ``R`` -- integer (optional); Number of rounds, starting with
              round ``0`` (rounds ``0, ..., R - 1``, at most ``N + 1``). The
              full cipher has ``R = N + 1`` rounds (``18`` for a 256-bit
              key), which is the default; a smaller ``R`` ends with a middle
              round.

            - ``key_schedule`` -- callable or
              :class:`civerly.keyschedule.KeySchedule` (optional); Key
              schedule used to derive round keys from ``key`` via
              ``set_round_keys``. Pass :class:`QALQAN_KeySchedule_CVL` (with
              matching ``R`` or the default, and matching ``key_size``) to use
              the real Qalqan key schedule, or
              :class:`civerly.keyschedule.DefaultKeySchedule_CVL` to pass
              explicit round keys (``R`` of them, 128 bits each, converted
              with :func:`qalqan_round_keys_to_components`). Defaults to
              ``None`` (no key schedule, all-zero round keys).

            - ``key`` -- bytes, integer or list of integers (optional); The
              master key passed to ``key_schedule``, immediately expanded and
              injected via ``set_round_keys`` when both are given. Has no
              effect when ``key_schedule`` is ``None``. When using
              :class:`civerly.keyschedule.DefaultKeySchedule_CVL`, this is the
              list of round keys (round key 0 first).

            - ``key_size`` -- integer (default: ``256``); Key size in bits
              (256 to 1024, in 128-bit steps). It determines ``N`` and hence
              which round is the final whitening round.

            - ``name`` -- string (default: ``"QALQAN"``); Name of the cipher.

        This cipher is "plug-and-play" usable, i.e. it can be directly used
        when imported.

        EXAMPLES:

        Default constructor (full 256-bit-key cipher, all-zero round keys)::

            sage: from civerly.cipher_implementations.qalqan import QALQAN_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: QALQAN_CVL().R
            18

        Full cipher with the 256-bit all-zero key::

            sage: from civerly.cipher_implementations.qalqan import (
            ....:   QALQAN_CVL, QALQAN_KeySchedule_CVL)
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: pt = 0x102030405060708090a0b0c0d0e0f
            sage: ks = QALQAN_KeySchedule_CVL()
            sage: cipher = QALQAN_CVL(key_schedule=ks, key=bytes(32))
            sage: vec_to_int(cipher(int_to_vec(pt, 128))) == \
            ....:   0xae19d9af6b1d9d3bd031b18783806c77
            True

        Basic encryption with a 256-bit key against a pre-computed known
        vector, once with the key schedule and once with explicit round keys
        via :class:`civerly.keyschedule.DefaultKeySchedule_CVL`::

            sage: from civerly.cipher_implementations.qalqan import (
            ....:   QALQAN_CVL, QALQAN_KeySchedule_CVL,
            ....:   qalqan_round_keys_to_components)
            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: key = bytes(range(32))                  # 256-bit key
            sage: rks = [
            ....:   0xdefc7d5097fc5b4689062b14bf944ca7,
            ....:   0x8f1410afec58fe73097f040930ca62f6,
            ....:   0x59b8d4f39153592d2c56419489e0ce9b,
            ....:   0x0598037b4d5fcdb61635965522839d7e,
            ....:   0xb6055ccf4068bbe604492238af11eee5,
            ....:   0xe4e5094f3ac1cea4d3557f423ce63b35,
            ....:   0x8aa4d21af28fd0544367d5b84ef07df6,
            ....:   0xb5ac1862e625a49acbf1d2d449f91c12,
            ....:   0x3187eb20d862bdf7eaf3a9ffe386f9d6,
            ....:   0x70edf6d9f0b2656e6cca9d7fc56b4271,
            ....:   0x78b0ef25aad592d0855c3ca0ce662d9b,
            ....:   0x93740497be2691c96dd4c0b8c66ad3cb,
            ....:   0x5a683593815984db2f7cfd83be31e644,
            ....:   0xe620e4e968e60d7b82c52c6a8bb42528,
            ....:   0xc000c8821b4f395633853905f669f412,
            ....:   0x71a9ec88e71db98432ec33a8e34cdd0e,
            ....:   0x02e4f4854d340fc17b1b87cee1f66973,
            ....:   0x9f4e6d1d76acc3c943a7ffe2f4d3614e,
            ....: ]
            sage: rks_cvl = qalqan_round_keys_to_components(rks)
            sage: ks(key) == rks_cvl
            True
            sage: pt = 0x102030405060708090a0b0c0d0e0f
            sage: ct_rks = vec_to_int(QALQAN_CVL(
            ....:     key_schedule=DefaultKeySchedule_CVL(128, 18), key=rks_cvl)(
            ....:     int_to_vec(pt, 128)
            ....:   ))
            sage: ct_key = vec_to_int(QALQAN_CVL(
            ....:     key_schedule=ks, key=key)(
            ....:     int_to_vec(pt, 128)
            ....:   ))
            sage: ct_rks == ct_key == 0x4a4dcffd1527032f1e5418e08d0f5a9d
            True

        A second, longer key (384 bit) also matches a known vector::

            sage: key = bytes(range(48))                  # 384-bit key
            sage: rks = [
            ....:   0x78a85a037a8bac1d0533335b5842596a,
            ....:   0x49dba62af577d7e6fe40915c6cc43d0d,
            ....:   0x6a997f65fd6823f2017d00e9da410f3b,
            ....:   0xb3f4570d58114114ede215a407af2f90,
            ....:   0xefebf52a7df5d3b14fba863bd582d5df,
            ....:   0x5ece47c5ee89dfb1d61c959065ae4d17,
            ....:   0xc54ae3ec3552a2fca469d61a9934ea3e,
            ....:   0x1a485a8851b4547edaa5503c7eca6d4d,
            ....:   0x02cb8c91b38578e383f5abd40947aa05,
            ....:   0x0be2c3da40f029b4f037e6f2a5cc3318,
            ....:   0xb94dbf919cd8133706b7c3f53b34f5de,
            ....:   0xff89cdb2869afcf16f57fabf55045a1b,
            ....:   0x7c86318a44e29be1202d3a59bdbdd58b,
            ....:   0xf7cec222625342c56a765312d151c23a,
            ....:   0x5acbbda287cc96425c6a884a273b6deb,
            ....:   0xae8c91ceca364c0c91de38c972a8b871,
            ....:   0x1d65731cca4cc11ecc663a4e6bd6f2c6,
            ....:   0xc4218cf8d363824e9ca8fbad760cb1f3,
            ....:   0xaf84d0d8e81a73cc22aec5a54ca11442,
            ....:   0x02c30281ebeac4ff6edc2ab711beaf99,
            ....: ]
            sage: rks_cvl = qalqan_round_keys_to_components(rks, key_size=384)
            sage: ks384 = QALQAN_KeySchedule_CVL(key_size=384)
            sage: ks384(key) == rks_cvl
            True
            sage: pt = 0x102030405060708090a0b0c0d0e0f10
            sage: ct_rks = vec_to_int(QALQAN_CVL(key_size=384,
            ....:     key_schedule=DefaultKeySchedule_CVL(128, 20), key=rks_cvl)(
            ....:     int_to_vec(pt, 128)
            ....:   ))
            sage: ct_key = vec_to_int(QALQAN_CVL(key_size=384,
            ....:     key_schedule=ks384, key=key)(
            ....:     int_to_vec(pt, 128)
            ....:   ))
            sage: ct_rks == ct_key == 0xccd671da0ec1add7c4dd8aec9918b3fc
            True

        Known vectors for longer keys (512-bit and 1024-bit) also match::

            sage: key = bytes(range(64))                  # 512-bit key
            sage: rks_512 = [
            ....:   0x78a85a037a8bac2d45ce9c56dbe295a8,
            ....:   0x27565f5c3cc8b962c147028195c7d7a3,
            ....:   0xdd317fc57cf3dcfe1294bfb4f14b0fd0,
            ....:   0xd7d7af56a45a08dccfd6ebede2fbf1d3,
            ....:   0x9681b8bb4d4dc589c9c9e95d60aeb6bd,
            ....:   0xd3f2567d352d0ec1e33d83deca94e8d4,
            ....:   0x523bac839605f6f6d4edac47e335b758,
            ....:   0xb45e63d13e4d95f7387dd983f7e60590,
            ....:   0x148bb97f63df218014951085f8d147f6,
            ....:   0xd17e1f188ffd1e2f3d2b756a7c641059,
            ....:   0xfee441463c69f5c1b56c85400a7fc280,
            ....:   0x6f05e3be10e17c4757d56e2246a8eb06,
            ....:   0x15728dea8fb5f0c6e010d4f2066d906a,
            ....:   0xc583de7d1d6c9fccfde45f85739257c3,
            ....:   0x668d40c8314fb8342fc91f7377fd07f8,
            ....:   0x314d9a24a0646e6f0c6fae5bf5ede792,
            ....:   0x15b8a376acd098ab099b3bcfbed94517,
            ....:   0x94b831d724a2a361f41b7e10440d3565,
            ....:   0x87a593161961b02a395d8587bfc47ad2,
            ....:   0xcb6b78191fa727794a5be2397a583441,
            ....:   0x63fedb79d2dabfe91c01b52724821bdc,
            ....:   0xb7aa3d885f6d254f3a737c205e4551eb,
            ....: ]
            sage: rks_cvl = qalqan_round_keys_to_components(rks_512, key_size=512)
            sage: ks512 = QALQAN_KeySchedule_CVL(key_size=512)
            sage: ks512(key) == rks_cvl
            True
            sage: pt = 0x102030405060708090a0b0c0d0e0f
            sage: ct_rks = vec_to_int(QALQAN_CVL(key_size=512,
            ....:     key_schedule=DefaultKeySchedule_CVL(128, 22), key=rks_cvl)(
            ....:     int_to_vec(pt, 128)
            ....:   ))
            sage: ct_key = vec_to_int(QALQAN_CVL(key_size=512,
            ....:     key_schedule=ks512, key=key)(
            ....:     int_to_vec(pt, 128)
            ....:   ))
            sage: ct_rks == ct_key == 0xe6087adfa9f9eff16423e8e4a2e2a2ba
            True

            sage: key = bytes(range(128))                 # 1024-bit key
            sage: rks_1024 = [
            ....:   0x78a85a037a8bac2d45ce9c56dbe295c8,
            ....:   0xa5ca283e6d70a5566ef1b0bee9560b86,
            ....:   0x59c2740f257d2eee64bf9eb632b82808,
            ....:   0x5e2a37e9f6699f4735a453bf6169fa8b,
            ....:   0x25daaab7f13a4a84abfddc6ba750c948,
            ....:   0xe61a5c5f0d37231e81e94a98c70a8f86,
            ....:   0x741bc8645825476eeaffb347f7d76ea8,
            ....:   0x54d0908f6294ae20463b3847534f16cd,
            ....:   0xbf5d76184a50e70486aa4c8344d5ec5f,
            ....:   0x38fa911e432e0b9b8dd8ca5fdd0ec189,
            ....:   0x0f02776331aef13fbfa9defe4fc3e84b,
            ....:   0x144913ae90e2dff64345c80bd1a3c26f,
            ....:   0x6ca2e0e11ddf1c42f9f7466882658c08,
            ....:   0xe89206eb853b5543cf86be1dc0046fa8,
            ....:   0xcd60c34e29d226b6feaecdf5250b0a1a,
            ....:   0x0504438c11bbee1d3a8d9a0ba3f7d383,
            ....:   0xcc8d82343fdfa479897631da5e2b090d,
            ....:   0xfe471b87e80708b612a371f9d63cfc46,
            ....:   0x374669bcb42acb5ac69343a053b79568,
            ....:   0x9b9c11bc3151ec39f036ff29aa4f66b6,
            ....:   0x12f7f39153fde1d555195f0e1831607b,
            ....:   0xbabed214c94ecc373d3625c845f99729,
            ....:   0xd0f5f131c56f9464ab9f7f2ebe779813,
            ....:   0x98b05cc7bb0726bf5885cd200aa809ee,
            ....:   0x4be87b0900bc4067640c848e659dda21,
            ....:   0xa3b00bbcdc41670b00505ded37a2f214,
            ....:   0x2a86308474fae27c54c6d6b5d7c5a41a,
            ....:   0x25272e333381ec19448b67d2b3e20b84,
            ....:   0xde96579ca87373bcc1afa50bf7a9dffc,
            ....:   0xbe018124754ea6562794e89b87604a59,
            ....: ]
            sage: rks_cvl = qalqan_round_keys_to_components(rks_1024, key_size=1024)
            sage: ks1024 = QALQAN_KeySchedule_CVL(key_size=1024)
            sage: ks1024(key) == rks_cvl
            True
            sage: ct_rks = vec_to_int(QALQAN_CVL(key_size=1024,
            ....:     key_schedule=DefaultKeySchedule_CVL(128, 30), key=rks_cvl)(
            ....:     int_to_vec(pt, 128)
            ....:   ))
            sage: ct_key = vec_to_int(QALQAN_CVL(key_size=1024,
            ....:     key_schedule=ks1024, key=key)(
            ....:     int_to_vec(pt, 128)
            ....:   ))
            sage: ct_rks == ct_key == 0x024003fa97d2ec44826428ca4d5f00d5
            True

        Truncated cipher using the ``R`` parameter, with a key schedule for
        ``R`` rounds or for the full cipher (extra round keys are ignored)::

            sage: key = bytes(range(32))
            sage: pt = int_to_vec(0x0102030405060708090a0b0c0d0e0f, 128)
            sage: rks_256bit = ks(key)
            sage: ct_trunc = vec_to_int(QALQAN_CVL(R=4,
            ....:     key_schedule=DefaultKeySchedule_CVL(128, 4),
            ....:     key=rks_256bit[:4])(pt))
            sage: ct_trunc_key = vec_to_int(QALQAN_CVL(R=4,
            ....:     key_schedule=QALQAN_KeySchedule_CVL(R=4), key=key)(pt))
            sage: ct_trunc_full = vec_to_int(QALQAN_CVL(R=4,
            ....:     key_schedule=ks, key=key)(pt))
            sage: ct_trunc == ct_trunc_key == ct_trunc_full == \
            ....:   0x433ed3214f19515e47fc9854fb317d79
            True

        Invalid round numbers are rejected::

            sage: QALQAN_CVL(R=19)
            Traceback (most recent call last):
            ...
            ValueError: R=19 exceeds N + 1 = 18 rounds for a 256-bit key.
            sage: QALQAN_CVL(R=0)
            Traceback (most recent call last):
            ...
            ValueError: R must be positive.

        Linear trail search on 3 rounds of Qalqan::

            sage: # optional - cryptominisat espresso
            sage: from civerly.cipher_implementations.qalqan import QALQAN_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = QALQAN_CVL(R=3)
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:       sat_solver=CRYPTOMINISAT_CVL(),
            ....:       logic_minimizer=ESPRESSO_CVL(),
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            Using existing file ..., make sure it is up to date!
            14176 variables and 94699 clauses were written to ...
            28
        """
        if key_size < 256 or key_size > 1024 or key_size % 128:
            raise ValueError("key_size must be 256..1024 bit, in 128-bit steps.")
        full_rounds = _rounds_for_key(key_size // 8)

        if R is None:
            R = full_rounds + 1
        R = int(R)
        if R < 1:
            raise ValueError("R must be positive.")
        if full_rounds + 1 < R:
            raise ValueError(
                f"R={R} exceeds N + 1 = {full_rounds + 1} rounds for a "
                f"{key_size}-bit key."
            )

        super().__init__(128, 128, R=R, key_schedule=key_schedule, key=key, name=name)

        # ---- reusable S-box layer -------------------------------------
        sbox_cipher = Cipher(128, 128, name="SBoxLayer")
        sb = SBox_CVL(SBox(SBOX), name="SBox")
        for j in range(16):
            node_sb = sbox_cipher.add_subcipher(
                sb, [(sbox_cipher.IN, (8 * j + b, b)) for b in range(8)]
            )
            sbox_cipher.add_output([(node_sb, (b, 8 * j + b)) for b in range(8)])

        # ---- reusable diffusion layer L -------------------------------
        l_cipher = Cipher(128, 128, name="L")

        def add8(a_node, a_off, b_node, b_off):
            return l_cipher.add_subcipher(
                ModAdd_CVL(8, name="Ladd"),
                [(a_node, (a_off + k, k)) for k in range(8)]
                + [(b_node, (b_off + k, 8 + k)) for k in range(8)],
            )

        IN = l_cipher.IN
        sum01 = add8(IN, 0, IN, 8)
        sum23 = add8(IN, 16, IN, 24)
        r0 = add8(sum01, 0, sum23, 0)
        sum45 = add8(IN, 32, IN, 40)
        sum67 = add8(IN, 48, IN, 56)
        r5 = add8(sum45, 0, sum67, 0)
        sum89 = add8(IN, 64, IN, 72)
        sum1011 = add8(IN, 80, IN, 88)
        r10 = add8(sum89, 0, sum1011, 0)
        sum1213 = add8(IN, 96, IN, 104)
        sum1415 = add8(IN, 112, IN, 120)
        r15 = add8(sum1213, 0, sum1415, 0)

        R0 = r0
        R4 = add8(IN, 32, r0, 0)
        R8 = add8(IN, 64, r0, 0)
        R12 = add8(IN, 96, r0, 0)
        R5 = r5
        R1 = add8(IN, 8, r5, 0)
        R9 = add8(IN, 72, r5, 0)
        R13 = add8(IN, 104, r5, 0)
        R10 = r10
        R2 = add8(IN, 16, r10, 0)
        R6 = add8(IN, 48, r10, 0)
        R14 = add8(IN, 112, r10, 0)
        R15 = r15
        R3 = add8(IN, 24, r15, 0)
        R7 = add8(IN, 56, r15, 0)
        R11 = add8(IN, 88, r15, 0)

        for node, j in [
            (R0, 0),
            (R1, 1),
            (R2, 2),
            (R3, 3),
            (R4, 4),
            (R5, 5),
            (R6, 6),
            (R7, 7),
            (R8, 8),
            (R9, 9),
            (R10, 10),
            (R11, 11),
            (R12, 12),
            (R13, 13),
            (R14, 14),
            (R15, 15),
        ]:
            l_cipher.add_output([(node, (b, 8 * j + b)) for b in range(8)])

        # ---- reusable 128-bit round-key addition (mod 2^128) ---------
        add128_cipher = Cipher(128, 128, name="Add128")
        rev_perm = [15 - c for c in range(16)]
        rev_in = add128_cipher.add_subcipher(
            PermuteLayer_CVL(rev_perm, word_coarseness=8, name="rev_in"),
            [(add128_cipher.IN, (i, i)) for i in range(128)],
        )
        rk_node = add128_cipher.add_subcipher(RK_CVL(128, const=0, name="rk"), [])
        modadd_node = add128_cipher.add_subcipher(
            ModAdd_CVL(128, name="ModAdd128"),
            [(rev_in, (i, i)) for i in range(128)]
            + [(rk_node, (i, 128 + i)) for i in range(128)],
        )
        rev_out = add128_cipher.add_subcipher(
            PermuteLayer_CVL(rev_perm, word_coarseness=8, name="rev_out"),
            [(modadd_node, (i, i)) for i in range(128)],
        )
        add128_cipher.add_output([(rev_out, (i, i)) for i in range(128)])

        # ---- reusable middle-round template (ADD, S, L) ---------------
        middle_round = Cipher(128, 128, name="QalqanRound")
        n_add = middle_round.add_subcipher(
            add128_cipher, [(middle_round.IN, (i, i)) for i in range(128)]
        )
        n_s = middle_round.add_subcipher(
            sbox_cipher, [(n_add, (i, i)) for i in range(128)]
        )
        n_l = middle_round.add_subcipher(l_cipher, [(n_s, (i, i)) for i in range(128)])
        middle_round.add_output([(n_l, (i, i)) for i in range(128)])

        # ---- assemble the full cipher ---------------------------------
        # Every round-key component is built with constant 0; the round keys
        # are injected via ``set_round_keys``.
        node = self.IN
        rk_paths = []

        for r in range(self.R):
            if r == 0:
                # Initial whitening XOR -> S -> L
                kw = RoundkeyXOR_CVL(128, 0, name="KeyAdd_start")
                node = self.add_subcipher(kw, [(node, (i, i)) for i in range(128)])
                rk_paths.append((node,))
                node = self.add_subcipher(
                    sbox_cipher, [(node, (i, i)) for i in range(128)]
                )
                node = self.add_subcipher(
                    l_cipher, [(node, (i, i)) for i in range(128)]
                )
            elif r == full_rounds:
                # Final whitening (no S, no L)
                kw = RoundkeyXOR_CVL(128, 0, name="KeyAdd_fin")
                node = self.add_subcipher(kw, [(node, (i, i)) for i in range(128)])
                rk_paths.append((node,))
            else:
                # ADD -> S -> L middle round
                node = self.add_subcipher(
                    middle_round, [(node, (i, i)) for i in range(128)]
                )
                rk_paths.append((node, n_add, rk_node))

        self.add_output([(node, (i, i)) for i in range(128)])

        # Round-key components as they live inside ``self`` (add_subcipher
        # deep-copies), one per round, in round order.
        self._rk_components = []
        for path in rk_paths:
            comp = self
            for n in path:
                comp = comp.nodes[n]
            self._rk_components.append(comp)

        if key_schedule is not None and key is not None:
            self.set_round_keys(key)


class QALQAN_KeySchedule_CVL(KeySchedule):
    def __init__(self, R=None, key_size=256, name="QALQAN_KeySchedule"):
        r"""
        The Qalqan key schedule as a CiVerLy DAG.

        The key schedule clocks two byte-wise shift registers ``A`` (17 bytes,
        initialized with the even-indexed key bytes and a zero byte) and ``B``
        (16 bytes, the odd-indexed key bytes). Per clock, a new byte is
        shifted into each register::

            A: S[A0] + S[A3] + A7 + S[A12] + A16 + e   (mod 256)
            B: S[B0] + B7 + S[B11] + B14 + S[B15] + e  (mod 256)

        where ``e`` is the next byte of the key bytes beyond the first 256
        bits, taken cyclically (``0`` for a 256-bit key). After every 17
        clocks, the round key ``A[i] + B[i] (mod 256)``, ``i = 0..15``, is
        output. Since no official test vectors exist, this reconstruction is
        what the CiVerLy test vectors are verified against.

        The round keys are output in the representation stored in the
        round-key components of :class:`QALQAN_CVL`: the whitening keys of
        rounds ``0`` and ``N`` are unchanged, while the keys of the middle
        rounds ``1, ..., N-1`` are byte-reversed (see
        :func:`qalqan_round_keys_to_components`).

        INPUT:

            - ``R`` -- integer (optional); Number of rounds of the cipher, with
              the same meaning and default as for :class:`QALQAN_CVL` (one
              round key per round, ``N + 1`` round keys for the full cipher).

            - ``key_size`` -- integer (default: ``256``); Key size in bits
              (256 to 1024, in 128-bit steps).

            - ``name`` -- string (default: ``"QALQAN_KeySchedule"``); Name of
              the key schedule.

        EXAMPLES::

            sage: from civerly.cipher_implementations.qalqan import (
            ....:   QALQAN_KeySchedule_CVL)
            sage: ks = QALQAN_KeySchedule_CVL()
            sage: ks.input_length, ks.output_length
            (256, 2304)
            sage: rks = ks(bytes(range(32)))
            sage: len(rks)
            18
            sage: [hex(rks[r]) for r in (0, 1, 17)]
            ['0xdefc7d5097fc5b4689062b14bf944ca7',
             '0xf662ca3009047f0973fe58ecaf10148f',
             '0x9f4e6d1d76acc3c943a7ffe2f4d3614e']
            sage: ks(int.from_bytes(bytes(range(32)), "big")) == rks
            True
            sage: QALQAN_KeySchedule_CVL(R=4)(bytes(range(32))) == rks[:4]
            True
            sage: len(QALQAN_KeySchedule_CVL(key_size=384)(0))
            20

        TESTS::

            sage: QALQAN_KeySchedule_CVL(R=19)
            Traceback (most recent call last):
            ...
            ValueError: R=19 exceeds N + 1 = 18 rounds for a 256-bit key.
            sage: QALQAN_KeySchedule_CVL()(bytes(48))
            Traceback (most recent call last):
            ...
            ValueError: Key has 384 bits, expected 256.
        """
        if key_size < 256 or key_size > 1024 or key_size % 128:
            raise ValueError("key_size must be 256..1024 bit, in 128-bit steps.")
        full_rounds = _rounds_for_key(key_size // 8)
        if R is None:
            R = full_rounds + 1
        R = int(R)
        if R < 1:
            raise ValueError("R must be positive.")
        if full_rounds + 1 < R:
            raise ValueError(
                f"R={R} exceeds N + 1 = {full_rounds + 1} rounds for a "
                f"{key_size}-bit key."
            )
        super().__init__(key_size, 128 * R, name=name)
        self.R = R
        self.key_size = key_size

        n_extra = key_size // 8 - 32
        step = self._make_round_step(n_extra > 0)

        def key_byte(j, dst):
            return [(self.IN, (8 * j + b, dst + b)) for b in range(8)]

        # Initial register state A[0..16] | B[0..15]: even key bytes, a zero
        # byte, odd key bytes.
        zero = self.add_subcipher(C_CVL(8, 0, name="zero"), [])
        state = [e for j in range(16) for e in key_byte(2 * j, 8 * j)]
        state += [(zero, (b, 128 + b)) for b in range(8)]
        state += [e for j in range(16) for e in key_byte(2 * j + 1, 136 + 8 * j)]

        extra_index = 0
        for r in range(R):
            edges = state
            if n_extra:
                # 34 extra key bytes per round key (one for A and one for B
                # per clock), taken cyclically from the key bytes 32, 33, ...
                for k in range(34):
                    edges = edges + key_byte(32 + extra_index, 264 + 8 * k)
                    extra_index = (extra_index + 1) % n_extra
            node = self.add_subcipher(step, edges)
            state = [(node, (i, i)) for i in range(264)]
            # Middle-round keys are stored byte-reversed (component format).
            reverse = 0 < r < full_rounds
            for j in range(16):
                dst = 128 * r + 8 * (15 - j if reverse else j)
                self.add_output([(node, (264 + 8 * j + b, dst + b)) for b in range(8)])

    @staticmethod
    def _make_round_step(with_extra):
        r"""
        The generation of one round key (17 clocks of both registers, then the
        round-key extraction) as a ``Cipher``.

        Input: the register state ``A[0..16] | B[0..15]`` (264 bits), followed
        by the 34 extra key bytes used by the 17 clocks if ``with_extra``.
        Output: the new register state (264 bits), followed by the 128-bit
        round key ``A[i] + B[i] (mod 256)``, ``i = 0..15``.

        The registers are not materialized per clock: every register byte is
        tracked as a ``(node, bit offset)`` source, so a clock only adds the
        S-boxes and modular additions of the two feedback bytes. The S-box
        output of a register byte is computed once and reused at all three
        tap positions it passes.
        """
        n_in = 264 + 34 * 8 * with_extra
        step = Cipher(n_in, 264 + 128, name="QalqanKSRound")
        sb = SBox_CVL(SBox(SBOX), name="SBox")
        sbox_cache = {}

        def sbox(src):
            if src not in sbox_cache:
                node = step.add_subcipher(
                    sb, [(src[0], (src[1] + b, b)) for b in range(8)]
                )
                sbox_cache[src] = (node, 0)
            return sbox_cache[src]

        def add(x, y):
            node = step.add_subcipher(
                ModAdd_CVL(8, name="KSadd"),
                [(x[0], (x[1] + b, b)) for b in range(8)]
                + [(y[0], (y[1] + b, 8 + b)) for b in range(8)],
            )
            return (node, 0)

        def chain(terms):
            acc = terms[0]
            for t in terms[1:]:
                acc = add(acc, t)
            return acc

        A = [(step.IN, 8 * j) for j in range(17)]
        B = [(step.IN, 136 + 8 * j) for j in range(16)]
        for t in range(17):
            terms_a = [sbox(A[0]), sbox(A[3]), A[7], sbox(A[12]), A[16]]
            terms_b = [sbox(B[0]), B[7], sbox(B[11]), B[14], sbox(B[15])]
            if with_extra:
                terms_a.append((step.IN, 264 + 16 * t))
                terms_b.append((step.IN, 272 + 16 * t))
            fa = chain(terms_a)
            fb = chain(terms_b)
            A = [*A[1:], fa]
            B = [*B[1:], fb]

        for j, src in enumerate(A + B):
            step.add_output([(src[0], (src[1] + b, 8 * j + b)) for b in range(8)])
        for j in range(16):
            rk = add(A[j], B[j])
            step.add_output([(rk[0], (b, 264 + 8 * j + b)) for b in range(8)])
        return step

    def eval(self, master_key):
        r"""
        Expand ``master_key`` into the list of the ``R`` round keys, in the
        representation expected by :class:`QALQAN_CVL`.

        INPUT:

            - ``master_key`` -- integer or bytes; The master key. A ``bytes``
              key is interpreted big-endian and must have ``key_size`` bits.

        OUTPUT: A list of ``R`` 128-bit integers, in round order.
        """
        from civerly.util import int_to_vec, vec_to_int

        if isinstance(master_key, (bytes, bytearray)):
            if len(master_key) * 8 != self.key_size:
                raise ValueError(
                    f"Key has {len(master_key) * 8} bits, expected {self.key_size}."
                )
            master_key = int.from_bytes(master_key, "big")
        bits = Cipher.eval(self, int_to_vec(int(master_key), self.input_length))
        return [vec_to_int(bits[128 * i : 128 * (i + 1)]) for i in range(self.R)]
