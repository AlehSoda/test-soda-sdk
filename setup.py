from setuptools import setup, find_packages

# Read requirements from the requirements.txt file
with open('requirements.txt') as f:
    install_requires = f.read().strip().split('\n')

setup(
    name='soda-python-sdk',
    version='0.1.2',
    packages=find_packages(where='python'),  # Look for packages in the 'python' directory
    package_dir={'': 'python'},  # Maps the root package to the 'python' directory
    description='This SDK provides functionalities for AES and RSA encryption schemes, ECDSA signature scheme and some functionalities used for working with sodalabs blockchain.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='sodalabs',
    author_email='aleh@sodalabs.io',
    url='https://github.com/AlehSoda/test-soda-sdk/',
    license='MIT',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
    install_requires=install_requires,
)
