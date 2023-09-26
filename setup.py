from setuptools import setup, find_packages

setup(
    name='EVM-Architect',
    version='0.3',
    packages=find_packages(),
    include_package_data=True,
    install_requires=open('requirements.txt').read().splitlines(),
    # metadata to display on PyPI
    author='David Desjardins',
    author_email='david.thegardens@gmail.com',
    description='Returns the architecture of a DeFi application with any given address',
    keywords='DeFi, Ethereum, Data, Smart Contracts, EVM',
    url='https://github.com/davidthegardens/EVM_Architect',
    classifiers=[
        'License :: OSI Approved :: Python Software Foundation License'
    ]
)