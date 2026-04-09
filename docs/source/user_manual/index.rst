===========
User Manual
===========

The CiVerLy Workflow
=====================

We first describe the CiVerLy workflow and the associated interfaces which we
visualize below.

.. figure:: workflow.png
   :name: fig:workflow

   The CiVerLy workflow.

In a nutshell, there are four steps.
We describe them briefly below and give more details on the respective pages.
For examples showcasing this, we refer to the ciphers already implemented in
CiVerLy, especially the AES and the corresponding examples that show how to use
CiVerLy to generate models for differential and linear cryptanalysis of AES.

**Implementing the Cipher**

The first step is to implement the cipher inside of CiVerLy.
The implementation has the form of a directed acyclic graph which consists of
components that come with CiVerLy.
For more details, see `Implementing the Cipher <implement_cipher.html>`_.

**Modeling the Cipher**

Once you have implemented the cipher, you can model it.
For this, you have to choose a model.
There are different models, varying in the complexity to solve them and the
accuracy of the results.
For more details, see `Modeling the Cipher <model_cipher.html>`_.

**Solving the Model**

Once you have the model, you need to solve it.
This is done with an external solver which might run on a different machine.
If CiVerLy and the solver are installed on the same machine, you can start the
solver from within CiVerLy.
For more details, see `Solving the Model <solve_model.html>`_.


**Generating the Report**

The final step is to generate the report.
This can be as simple as printing e.g. the number of active S-boxes but you can
also generate a PDF containing the details of the found trail.
For more details, see `Generating the Report <generate_report.html>`_.

**Exporting the Results**

You can also export the results of your last analysis into a json file.
This allows you to externally access and postprocess all your results later on.
For more details, see `Exporting the Results <export_trail.html>`_.



.. toctree::
   :hidden:
   :maxdepth: 1

   implement_cipher
   model_cipher
   solve_model
   generate_report
   export_trail
