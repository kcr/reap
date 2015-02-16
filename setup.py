#!/usr/bin/python3
import setuptools

setuptools.setup(
    name='reap',
    version='0',
    description='Regular Expression Automatons for Python',
    url='https://github.com/kcr/reap',
    author='Karl Ramm',
    author_email='karl.ramm@gmail.com',
    license='BSD',
    classifiers=[
        'Programming Language :: Python',
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        ],
    py_modules=['reap'],
    install_requires=['rply'],
    )
