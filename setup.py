from setuptools import setup, find_packages

import pdnsupdate

setup(
    name='pdnsupdate',
    version=pdnsupdate.__version__,
    packages=find_packages(),
    author='Benoit SAGE',
    author_email='benoit.sage@gmail.com',
    description="Update dinamicaly public address on RFC2136 DNS",
    long_description=open('README.rst').read(),
    install_requires=['requests', 'dnspython'],
    include_package_data=True,
    url='http://github.com/bugsbriez/pdnsupdate',
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 1 - Planning",
        "License :: BSD-3",
        "Natural Language :: French",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.6",
        "Topic :: Network",
    ],
)