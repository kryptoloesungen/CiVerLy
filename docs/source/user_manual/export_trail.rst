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
    sage: import tempfile
    sage: cipher = PRESENT_CVL(4)
    sage: tmpdir = tempfile.mkdtemp()
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
    5312 variables and 8641 constraints were written to ...
    12
    sage: input_difference = cipher.results[0]['in']
    sage: output_difference = cipher.results[0]['out']
    sage: # Export the cipher together with its results
    sage: export_file = model_options.path / f"{cipher.name}.json"
    sage: cipher.export(export_file)
    Writing problem data to...
    31602 records were written
    Object 'PRESENT' has been exported to ...
    sage: # Load the cipher from scratch
    sage: loaded = cipher.load(export_file)
    sage: # The results are still the same
    sage: loaded.results[0]['in'] == input_difference
    True
    sage: loaded.results[0]['out'] == output_difference
    True
    sage: # Overall, the ciphers are entirely the same
    sage: sorted(loaded.__dict__) == sorted(cipher.__dict__)
    True
    sage: import shutil
    sage: shutil.rmtree(tmpdir)


