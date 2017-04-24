import codecs
import os
import sys
import setuptools


here = os.path.abspath(os.path.dirname(__file__))
readme = codecs.open(os.path.join(here, 'README.md'), encoding='utf-8').read()

install_requires = [
    'acme>=0.11,<0.12',
    'boto3>=1,<2',
    'dnspython>=1.15.0,<2',
    'ovh>=0.4.7,<0.5',
    'pycrypto==2.6.1',
    'pyOpenSSL',
    'pytz',
    'PyYAML>=3.11,<3.12',
    'requests',
]

if sys.version_info < (2, 7):
    install_requires.extend([
        'argparse',
#        'mock<1.1.0',
    ])
#else:
#    install_requires.extend([
#        'mock',
#    ])

#tests_require = [
#    'pep8',
#    'pylint',
#]

setuptools.setup(
    name='LetsLambda',
    author='Aurelien Requiem',
    author_email='aurelien.requiem@gmail.com',
    description="Let's Encrypt Client for AWS Lambda",
    long_description=readme,
    license='GPLv3',
    url='https://github.com/aureq/letslambda',
    py_modules=['letslambda'],
    setup_requires=['setuptools_scm'],
    use_scm_version=True,
    install_requires=install_requires,
#    extras_require={
#        'tests': tests_require,
#    },
    entry_points={
        'console_scripts': [
            'letslambda = letslambda:main',
        ],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],
)
