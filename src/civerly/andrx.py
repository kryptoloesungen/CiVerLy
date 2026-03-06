r"""
``AndRX`` is a subclass of ``WordBasedCipher``, in which the non-linear
components ``ModAdd_CVL`` and ``SBox_CVL`` are not allowed.

The main purpose of this class is to support SAT modeling techniques for
``SIMON``-like ciphers.

EXAMPLES::

    sage: from civerly.andrx import AndRX
    sage: from civerly.component import XOR_CVL, AND_CVL, SBox_CVL
    sage: from sage.crypto.sboxes import AES
    sage: andrx_cipher = AndRX(32, 2, 2, "AndRXCipher")
    sage: edges = [(andrx_cipher.IN, (0, 0)), (andrx_cipher.IN, (1, 1))]
    sage: node_xor = andrx_cipher.add_subcipher(XOR_CVL(32, name="xor"), edges)
    sage: edges = [(node_xor, (0, 0)), (andrx_cipher.IN, (1, 1))]
    sage: node_and = andrx_cipher.add_subcipher(AND_CVL(32, name="and"), edges)
    sage: andrx_cipher.add_subcipher(SBox_CVL(AES), [(node_and, (0, 0))])
    Traceback (most recent call last):
    ...
    TypeError: AndRX does not accept SBox_CVL and ModAdd_CVL
"""

from civerly.wordbasedcipher import WordBasedCipher
from civerly.component import Component, SBox_CVL, ModAdd_CVL


class AndRX(WordBasedCipher):
    def add_subcipher(self, sub_cipher, edges):
        r"""
        The edges are now reduced. Instead of w many edges going into the same
        node anyway, we just say that one edge (of size w) goes into that node.

        EXAMPLES::

            sage: from civerly.cipher import Cipher
            sage: from civerly.wordbasedcipher import WordBasedCipher
            sage: from civerly.andrx import AndRX
            sage: from civerly.component import AND_CVL
            sage: wbc = WordBasedCipher(8, 16, 16, "WBC")
            sage: edges = [(wbc.IN, (1, 0)), (wbc.IN, (2, 1))]
            sage: node = wbc.add_subcipher(AND_CVL(8), edges)
            sage: andrx = AndRX(8, 16, 16, "ARXCipher")
            sage: edges = [(andrx.IN, (1, 0)), (andrx.IN, (2, 1))]
            sage: node = andrx.add_subcipher(AND_CVL(8), edges)
            sage: wbc == andrx
            True
            sage: cipher = Cipher(128, 128, "Cipher")
            sage: edges = [(cipher.IN, (i + 8, i)) for i in range(16)]
            sage: node = cipher.add_subcipher(AND_CVL(8), edges)
            sage: cipher == wbc
            True
            sage: cipher == andrx
            True
        """
        if isinstance(sub_cipher, (AndRX, Component)):
            if not isinstance(sub_cipher, (SBox_CVL, ModAdd_CVL)):
                return super().add_subcipher(sub_cipher, edges)
            raise TypeError("AndRX does not accept SBox_CVL and ModAdd_CVL")
        raise TypeError(f"Trying to add illegal component {type(sub_cipher)}.")
