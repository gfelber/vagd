import os
import sys
import toml

# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

pyproject = toml.load('../pyproject.toml') 
project = pyproject['project']['name'].upper()
copyright = '2024, 0x6fe1be2'
author = pyproject['project']['authors'][0]['name']
release = pyproject['project']['version']

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
  'sphinx.ext.autodoc', 
  'sphinx.ext.autosummary',
  'sphinx.ext.napoleon', 
  'sphinxcontrib.jquery',
  'autoapi.extension',
]

sys.path.insert(0, os.path.abspath('../src'))
autoapi_dirs = ['../src/vagd']
autoclass_content = 'both'

templates_path = ['_templates']
autoapi_ignore = exclude_patterns = ['*env*', '*__pycache__*', '*.egg-info' , '*vagd/gdb/*']
autoapi_add_toctree_entry = False



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

