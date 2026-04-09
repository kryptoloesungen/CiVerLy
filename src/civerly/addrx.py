r"""
``AddRX`` is a subclass of ``WordBasedCipher``, in which the non-linear
components ``AND_CVL`` and ``SBox_CVL`` are not allowed.

The main purpose of this class is to support SAT modeling techniques for
various AddRX designs.

EXAMPLES::

    sage: from sage.crypto.sbox import SBox
    sage: from civerly.addrx import AddRX
    sage: from civerly.component import ModAdd_CVL, AND_CVL, SBox_CVL
    sage: addrx = AddRX(4, 4, 4, "Cipher")
    sage: edges = [(addrx.IN, (0, 0)), (addrx.IN, (1, 1))]
    sage: addrx.add_subcipher(AND_CVL(4), edges)
    Traceback (most recent call last):
    ...
    TypeError: AddRX does not accept SBox_CVL and AND_CVL
    sage: e = [(addrx.IN, (0, 0))]
    sage: addrx.add_subcipher(SBox_CVL(SBox([0,1,4,3,6,5,2,7])), e)
    Traceback (most recent call last):
    ...
    TypeError: AddRX does not accept SBox_CVL and AND_CVL
    sage: edges = [(addrx.IN, (i, i)) for i in range(4)]
    sage: node = addrx.add_subcipher(ModAdd_CVL(8), edges)
"""

from civerly.wordbasedcipher import WordBasedCipher
from civerly.component import Component, SBox_CVL, AND_CVL


class AddRX(WordBasedCipher):
    def add_subcipher(self, sub_cipher, edges):
        r"""
        The edges are now reduced. Instead of w many edges going into the same
        node anyway, we just say that one edge (of size w) goes into that node.

        EXAMPLES::

            sage: from civerly.cipher import Cipher
            sage: from civerly.wordbasedcipher import WordBasedCipher
            sage: from civerly.addrx import AddRX
            sage: from civerly.component import ModAdd_CVL
            sage: wbc = WordBasedCipher(8, 16, 16, "WBC")
            sage: edges = [(wbc.IN, (1, 0)), (wbc.IN, (2, 1))]
            sage: node = wbc.add_subcipher(ModAdd_CVL(8), edges)
            sage: addrx = AddRX(8, 16, 16, "ARXCipher")
            sage: edges = [(addrx.IN, (1, 0)), (addrx.IN, (2, 1))]
            sage: node = addrx.add_subcipher(ModAdd_CVL(8), edges)
            sage: wbc == addrx
            True
            sage: cipher = Cipher(128, 128, "Cipher")
            sage: edges = [(cipher.IN, (i + 8, i)) for i in range(16)]
            sage: node = cipher.add_subcipher(ModAdd_CVL(8), edges)
            sage: cipher == wbc
            True
            sage: cipher == addrx
            True
        """
        if isinstance(sub_cipher, (AddRX, Component)):
            if not isinstance(sub_cipher, (SBox_CVL, AND_CVL)):
                return super().add_subcipher(sub_cipher, edges)
            raise TypeError("AddRX does not accept SBox_CVL and AND_CVL")
        raise TypeError(f"Trying to add illegal component {type(sub_cipher)}.")

    def _to_dict(self):
        d = super()._to_dict()
        d["type"] = "AddRX"
        return d
