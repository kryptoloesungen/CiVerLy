'''
Docstring for civerly.cipher_implementations.midori
Midori is a family of 2 block ciphers: Midori64 and Midori 128.
They both accept key length of 128 bits.
It is a SPN cipher and consists of S-layer (SubCell) and P-layer (ShuffleCell & MixColumn) and KeyAdd 
The state is represented by a 4x4 matrix
Midori64:
    block size  of 64 bits
    key length of 128 bits 
    cell size in the 4x4 matrix is 4 bits
    number of rounds is 16
    Sb0[x]
Midori128:
    block size  of 64 bits
    key length of 128 bits
    cell size in the 4x4 matrix is 8 bits
    number of rounds is 20
    Sb1[x]
    uses 4 different 8-bit S-Boxes: SSb0, SSb1, SSb2 and SSb3

SubCell:
    Midori64:
        Sb0 is applied to every 4-bit cell of the state in parallel
        si ← Sb0[si]
    Midori128:
        SSBi are applied to every 8-bit cell of the state in parallel
        si ← SSb(i mod 4)[si] 0 <= i <= 15

ShuffleCell:
    Midori64 & Midori128:
        (s0, s1, ..., s15) ← (s0, s10, s5, s15, s14, s4, s11, s1, s9, s3, s12, s6, s7, s13, s2, s8)

MixColumn:
    Midori64 & Midori128:
        M is applied to every 4m bit column of the state
        t(si, si+1, si+2, si+3) ← M(t)*(si, si+1, si+2, si+3) and i = 0, 4, 8, 12
KeyAdd:
    Midori64 & Midori128:
        The ith n-bit round key RKi is XORed to a state S

Function:
    keyAdd(X,Wk)
    for i= 0..R-2
        SubCell(S)
        ShuffleCell(S)
        MixColumn(S)
        KeyAdd(S)
    SubCell(S)
    KeyAdd(S, WK)
'''