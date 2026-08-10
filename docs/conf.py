import os
import sys
import toml

# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

pyproject = toml.load("../pyproject.toml")
project = pyproject["project"]["name"].upper()
copyright = "2025, 0x6fe1be2"
author = pyproject["project"]["authors"][0]["name"]
release = pyproject["project"]["version"]

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
  "sphinx.ext.autodoc",
  "sphinx.ext.autosummary",
  "sphinx.ext.napoleon",
  "sphinxcontrib.jquery",
  "autoapi.extension",
]

sys.path.insert(0, os.path.abspath("../src"))
autoapi_dirs = ["../src/vagd"]
autoclass_content = "both"

templates_path = ["_templates"]
exclude_patterns = ["_build", "env", "Thumbs.db", ".DS_Store"]
autoapi_ignore = ["*__pycache__*", "*.egg-info"]
autoapi_add_toctree_entry = True


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]
html_theme_options = {
  # Keep the complete package/module tree visible in the left sidebar.
  "collapse_navigation": False,
  "includehidden": True,
  "navigation_depth": 5,
  # Classes and functions remain on their module pages instead of cluttering
  # the navigation tree.
  "titles_only": True,
}
