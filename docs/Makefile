# Makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
PAPER         =
BUILDDIR      = build

ALLSPHINXOPTS   = -d $(BUILDDIR)/doctrees $(SPHINXOPTS) source

.PHONY: clean html latex pdf

clean:
	rm -rf $(BUILDDIR)/*

html:
	$(SPHINXBUILD) -b html $(ALLSPHINXOPTS) $(BUILDDIR)/html
	@echo
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/html."

latex:
	$(SPHINXBUILD) -b latex $(ALLSPHINXOPTS) $(BUILDDIR)/latex
	@echo
	@echo "Build finished. The LaTeX sources are in $(BUILDDIR)/latex."

pdf: latex
	cd $(BUILDDIR)/latex && $(MAKE)
	mkdir -p $(BUILDDIR)/pdf
	cp $(BUILDDIR)/latex/civerly.pdf $(BUILDDIR)/pdf/civerly.pdf
