=================
The Documentation
=================

We build the documentation of CiVerLy (this document) using `Sphinx <https://www.sphinx-doc.org>`_.
That is, we essentially mimic what ``sage`` is doing as well.
The actual source code is documented using so called docstrings at the beginning of a class or function.
These are augmented by additional documentation which is stored in ``.rst`` files in the aforementioned ``docs/source/`` directory.
Sphinx then processes these files and the docstrings to build the documentation.
Notice that Sphinx already comes with ``sage`` and hence is no additional dependency.

The available formats for the documentation are HTML and PDF.
The HTML version can either be used by opening the corresponding ``.html`` files locally in a web browser or by making them available on a web server.
As we expect the documentation to usually be not consumed in a read beginning-to-end form, we recommend to use the HTML version for day-to-day use and the PDF version for archiving.

Rebuilding the Documentation
============================

The documentation of CiVerLy (this document) is build using Sphinx.
To modify it, either edit the docstrings in the Python source files of CiVerLy
or edit the files in ``civerly/docs/source``.

To build the HTML documentation, run the following command in the project root:

.. code-block:: console

   $ nix build .#docs-html

The result will be in ``result/``.

To build the PDF version of the documentation run:

.. code-block:: console

   $ nix build .#docs-pdf

The resulting PDF will be at ``result/civerly.pdf``.
