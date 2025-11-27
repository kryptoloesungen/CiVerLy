.. nodoctest


Component
=================

Generic Component
------------------------

.. autoclass:: civerly.component.Component
   :members: __init__
   :private-members: 
   :undoc-members:
   :show-inheritance:
   :exclude-members: __call__, _init_model, _model_sat, _model_milp, eval, input_length, output_length, name, _to_tikz, _abc_impl, const, word_length, binary_matrix, word_coarseness,   

Identity Component
------------------------

.. autoclass:: civerly.component.I_CVL
   :members:
   :private-members: 
   :undoc-members:
   :show-inheritance:
   :exclude-members: __init__, _abc_impl, __repr__, _model_milp, _model_sat

Constant Component
------------------------

.. autoclass:: civerly.component.C_CVL
   :members:
   :private-members: 
   :undoc-members:
   :show-inheritance:
   :exclude-members: __init__, _abc_impl, const, eval, __repr__, _model_milp, _model_sat

RoundKey Component
------------------------

.. autoclass:: civerly.component.RK_CVL
   :members:
   :private-members: 
   :undoc-members:
   :show-inheritance:
   :exclude-members: __init__, _abc_impl, const, eval, __repr__

ConstXOR Component
------------------------

.. autoclass:: civerly.component.ConstXOR_CVL
   :members:
   :private-members: 
   :undoc-members:
   :show-inheritance:
   :exclude-members: __init__, _abc_impl, const, eval, __repr__, _model_milp, _model_sat

RoundkeyXOR Component 
------------------------

.. autoclass:: civerly.component.RoundkeyXOR_CVL
   :members:
   :private-members: 
   :undoc-members:
   :show-inheritance:
   :exclude-members: __init__, _abc_impl, const, eval, __repr__

XOR Component 
------------------------

.. autoclass:: civerly.component.XOR_CVL
   :members:
   :private-members: 
   :undoc-members:
   :show-inheritance:
   :exclude-members: __init__, _abc_impl, word_length, eval, __repr__, _model_milp, _model_sat

ModAdd Component
------------------------

.. autoclass:: civerly.component.ModAdd_CVL
   :members:
   :private-members: 
   :undoc-members:
   :show-inheritance:
   :exclude-members: __init__, _abc_impl, word_length, eval, __repr__, _model_milp, _model_sat

AND Component 
------------------------

.. autoclass:: civerly.component.AND_CVL
   :members:
   :private-members: 
   :undoc-members:
   :show-inheritance:
   :exclude-members: __init__, _abc_impl, word_length, eval, __repr__, _model_milp, _model_sat

Linear Layer Component 
------------------------

.. autoclass:: civerly.component.LinearLayer_CVL
   :members:
   :private-members: 
   :undoc-members:
   :show-inheritance:
   :exclude-members: __init__, _abc_impl, inv, eval, __repr__, _model_milp, _model_sat, binary_matrix, _milp_bitwise, _milp_wordwise, _sat_bitwise

   .. automethod:: civerly.component.LinearLayer_CVL._milp_bitwise
      :no-index:

Permutation Layer Component 
------------------------------

.. autoclass:: civerly.component.PermuteLayer_CVL
   :members:
   :private-members: 
   :undoc-members:
   :show-inheritance:
   :exclude-members: __init__, _abc_impl, perm, word_coarseness, eval, __repr__, _model_milp, _model_sat, inv

   

Rotation Layer Component 
------------------------------

.. autoclass:: civerly.component.RotateLayer_CVL
   :members:
   :private-members: 
   :undoc-members:
   :show-inheritance:
   :exclude-members: __init__, _abc_impl, r, word_coarseness, eval, __repr__, _model_milp, _model_sat, inv

SBox Component 
------------------------

.. autoclass:: civerly.component.SBox_CVL
   :members:
   :private-members: 
   :undoc-members:
   :show-inheritance:
   :exclude-members: __init__, _abc_impl, inv, eval, __repr__, _model_milp, _model_sat, S, _milp_bitwise, _milp_wordwise, _sat_bitwise

AND Component With Rotated Inputs
-----------------------------------

.. autoclass:: civerly.component.ROT_AND_CVL
   :members:
   :private-members: 
   :undoc-members:
   :show-inheritance:
   :exclude-members: __init__, _abc_impl, __call__, _model_sat, _model_milp, eval, input_length, output_length, name, _to_tikz, _abc_impl, const, word_length, binary_matrix, word_coarseness, S, SMALL_SBOX_SIZE
