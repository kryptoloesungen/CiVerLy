Exporting the Results
=======================

CiVerLy supports exporting Cipher objects into a json file.
As Cipher objects also contain the trails coming from previous runs of :meth:`analysis`,
it is possible to directly access those results from outside of CiVerLy,
allowing to seamlessly incorporate them into your workflow.

See the following example to understand how to export and load Cipher objects.

.. code-block::
    # First, analyse some cipher
    from civerly.cipher_implementations.present import PRESENT_CVL
    from civerly.model_options import *
    cipher = PRESENT_CVL(4)
    model_options = MODEL_OPTIONS(
        optimization=OPTIMIZATION.MILP,
        cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        granularity=GRANULARITY.BITWISE,
        sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
        milp_solver=GUROBI_CVL(),
        linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
        logic_minimizer=ESPRESSO_CVL(),
        path=Path("export-example")
    )
    cipher.analyse(model_options)
    input_difference = cipher.result['in']
    output_difference = cipher.result['out']
   
    # Export the cipher together with its results
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        tmpfile_name = f.name
    cipher.export(tmpfile_name)
   
    # Load the cipher from scratch
    loaded = cipher.load(tmpfile_name)
    
    # The results are still the same
    loaded.result['in'] == input_difference
    loaded.result['out'] == output_difference


