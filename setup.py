from pathlib import Path

from setuptools import find_packages, setup

setup(
    name='aioacme',
    version='0.0.0',
    python_requires='>=3.10',
    url='https://github.com/tkukushkin/aioacme',
    author='Timofei Kukushkin',
    author_email='tima@kukushkin.me',
    description='Async ACME client implementation',
    long_description=(Path(__file__).parent / 'README.md').read_text('utf-8'),
    long_description_content_type='text/markdown',
    license='MIT',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    include_package_data=True,
    install_requires=[
        'aiohttp',
        'cryptography',
        'typing-extensions; python_version<"3.11"',
        'orjson',
        'serpyco-rs',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    project_urls={
        'Source': 'https://github.com/tkukushkin/aioacme',
    },
)
