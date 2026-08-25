Exporting the Results
=======================

CiVerLy supports exporting Cipher objects into a json file.
As Cipher objects also contain the trails coming from previous runs of :meth:`analyse`,
it is possible to directly access those results from outside of CiVerLy,
allowing to seamlessly incorporate them into your workflow.

See the following example to understand how to export and load Cipher objects.

.. code-block::

    sage: # optional - scip, espresso
    sage: # First, analyse some cipher
    sage: from civerly.cipher_implementations.present import PRESENT_CVL
    sage: from civerly.model_options import *
    sage: cipher = PRESENT_CVL(4)
    sage: model_options = MODEL_OPTIONS(
    ....:     optimization=OPTIMIZATION.MILP,
    ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
    ....:     granularity=GRANULARITY.BITWISE,
    ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
    ....:     milp_solver=SOLVER.SCIP,
    ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
    ....:     logic_minimizer=SOLVER.ESPRESSO,
    ....:     path=Path("export-example")
    ....: )
    sage: cipher.analyse(model_options)
    5312 variables and 8641 constraints were written to 'export-example/PRESENT.mps'
    12
    sage: # input_difference = cipher.results[0]['in']
    sage: # output_difference = cipher.results[0]['out']
    sage: # # Export the cipher together with its results
    sage: # import tempfile
    sage: # f = tempfile.NamedTemporaryFile(suffix='.json', delete=False)
    sage: # tmpfile_name = f.name
    sage: # cipher.export(tmpfile_name)
    sage: # # Load the cipher from scratch
    sage: # loaded = cipher.load(tmpfile_name)
    sage: # # The results are still the same
    sage: # loaded.results[0]['in'] == input_difference
    sage: # loaded.results[0]['out'] == output_difference


