"""setup.py for simpleldapauth"""

from setuptools import setup


setup(
    name="simpleldapauth",
    version="1.0.0",
    author="bennr01",
    author_email="benjamin99.vogt@web.de",
    description="Simple LDAP authentication code based on kadi4mat's LDAP code",
    long_description=open("README.md").read(),
    license="MIT",
    keywords="ldap authentication",
    url="https://github.com/bennr01/simpleldapauth/",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP",
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python :: 3",
        ],
    packages=[
        "simpleldapauth",
        ],
    install_requires=[
        "ldap3",
        ],
    )
