from sage.misc.sagedoc_conf import skip_TESTS_block


# this removes TESTS blocks from the documentation
def setup(app):
    app.connect('autodoc-process-docstring', skip_TESTS_block)
