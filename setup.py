#!/usr/bin/env python3

from distutils.core import setup

setup(
    name="radicale_rights_ldap",
    version="0.2",
    description="LDAP Rights Plugin for Radicale 3",
    author="Andrey Kunitsyn",
    license="GNU GPL v3",
    install_requires=["radicale >= 3.3.0"],
    packages=["radicale_rights_ldap"])
