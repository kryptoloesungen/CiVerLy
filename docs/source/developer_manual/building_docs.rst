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

Contributing to the Documentation
=================================

This section explains how to contribute improvements to the CiVerLy documentation.
It is aimed at both developers and users who want to help make the docs clearer,
more complete, or better structured.

Where documentation lives
-------------------------

- The main narrative documentation is written in reStructuredText (``.rst``)
  files under ``docs/source/``.
- The user and developer manuals live in
  ``docs/source/user_manual/`` and ``docs/source/developer_manual/``.
- The API / source code documentation is generated from docstrings in the
  Python modules under ``src/civerly/`` and from the ``.rst`` files in
  ``docs/source/documentation/``.

When you are unsure where to place new content, try to follow the existing
structure:

- High-level workflows and conceptual explanations usually belong in the
  user manual.
- Project internals, architecture, and development processes belong in the
  developer manual.
- Detailed reference material for individual classes and functions belongs
  in the API documentation.

Style guidelines
----------------

- Use clear, concise English.
- Prefer “CiVerLy”, “SageMath”, “MILP”, and “SAT” with this capitalization.
- Use standard Sphinx / reStructuredText constructs (``.. code-block::``,
  ``.. figure::``, ``.. note::``, and ``:ref:`` labels) and follow the
  surrounding style in the file you are editing.
- Keep headings consistent with the rest of the documentation and use
  sentence case for normal text.
- For commands and code, use ``.. code-block:: console`` or an appropriate
  language (for example, ``.. code-block:: sage``) and indent the content
  by three spaces.

Previewing changes locally
--------------------------

Before submitting changes, it is recommended to build the documentation
locally to check for formatting issues and Sphinx warnings.

If you are using Nix (recommended), from the project root run:

.. code-block:: console

   $ nix build .#docs-html

The generated HTML documentation will appear under ``result/``. Open the
``index.html`` file in a web browser to review your changes.

To build the PDF version, run:

.. code-block:: console

   $ nix build .#docs-pdf

This produces ``result/civerly.pdf``.

If you are not using Nix, you can still use Sphinx directly, but note that
this requires a suitable Python environment with Sphinx and the CiVerLy
dependencies installed. In most cases, using the Nix-based workflow above
is the simplest option.

Submitting documentation changes
--------------------------------

When you are happy with your changes:

- Ensure that the docs build without errors or warnings, if possible.
- Keep commits focused (for example, “Fix typos in installation docs” or
  “Add section on running tests in CI”).
- Open a pull request describing what you changed and why, and mention
  any sections of the docs you would like reviewers to pay particular
  attention to.
