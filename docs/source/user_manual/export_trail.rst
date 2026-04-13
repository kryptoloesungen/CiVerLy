Exporting the Results
=======================

CiVerLy supports exporting Cipher objects into a json file.
As Cipher objects also contain the trails coming from previous runs of :meth:`analysis`,
it is possible to directly access those results from outside of CiVerLy,
allowing to seamlessly incorporate them into your workflow.

See the following example to understand how to export and load Cipher objects.

.. code-block:: sage

    sage: # First, analyse some cipher
    sage: from civerly.cipher_implementations.present import PRESENT_CVL
    sage: from civerly.model_options import *
    sage: cipher = PRESENT_CVL(4)
    sage: model_options = MODEL_OPTIONS(
    ....:   optimization=OPTIMIZATION.MILP,
    ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
    ....:   granularity=GRANULARITY.BITWISE,
    ....:   sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
    ....:   milp_solver=SCIP_CVL(),
    ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
    ....:   logic_minimizer=ESPRESSO_CVL(),
    ....:   path=Path("export-example"))
    sage: cipher.analyse(model_options)
    sage: input_difference = cipher.result['in']
    sage: output_difference = cipher.result['out']

    sage: # Export the cipher together with its results
    sage: import tempfile
    sage: with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
    ....:   tmpfile_name = f.name
    ....:   cipher.export(tmpfile_name)
    ....:   # Load the cipher from scratch
    ....:   loaded = cipher.load(tmpfile_name)
    ....:   # The results are still the same
    ....:   print(loaded.result['in'] == input_difference)
    ....:   print(loaded.result['out'] == output_difference)
    Object 'PRESENT' has been exported to ...
    True
    True


