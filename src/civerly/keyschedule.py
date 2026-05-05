from civerly.cipher import Cipher


class KeySchedule(Cipher):
    """
    Base class for cipher key schedules implemented as CiVerLy DAGs.

    A KeySchedule takes master key bits as input and outputs all round key
    bits concatenated. Use ``set_master_key`` on the main cipher to evaluate
    the key schedule and inject round keys into the cipher's RK components.
    """
    pass
