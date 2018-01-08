"""
Scumblr-Spillguard
==================

Processes github commit events to look for known secrets.
"""
import sys
import os.path

from setuptools import setup, find_packages


ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__)))

# When executing the setup.py, we need to be able to import ourselves, this
# means that we need to add the src/ directory to the sys.path.
sys.path.insert(0, ROOT)

about = {}
with open(os.path.join(ROOT, "scumblr_spillguard", "__about__.py")) as f:
    exec(f.read(), about)


install_requires = [
    'requests==2.11.1',
    'retrying',
    'raven_python_lambda'
]

tests_require = [
    'pytest',
    'responses'
]


setup(
    name=about["__title__"],
    version=about["__version__"],
    author=about["__author__"],
    author_email=about["__email__"],
    url=about["__uri__"],
    description=about["__summary__"],
    long_description='See README.md',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=install_requires,
    extras_require={
        'tests': tests_require
    },
    keywords=['github', 'secret_management'],
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ],
)