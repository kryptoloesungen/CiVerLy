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
In case you modified the Python sources, you first have to reinstall CiVerLy by running

.. code-block:: console

   $ sage --python -m pip install --no-index --no-build-isolation .

in the ``civerly`` directory.
Now, change the directory to the ``civerly/docs`` directory.
Then, to build the HTML documentation run:

.. code-block:: console

   $ sage -sh -c "make html"

To build the PDF version of the documentation run:

.. code-block:: console

   $ sage -sh -c "make pdf"

