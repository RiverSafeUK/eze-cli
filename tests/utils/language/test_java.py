# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long,invalid-name
from eze.utils.language.java import ignore_groovy_errors


def test_ignore_groovy_errors__remove_groovy_messages():
    test_input = """WARNING: An illegal reflective access operation has occurred
WARNING: Illegal reflective access by com.google.inject.internal.cglib.core.$ReflectUtils$1 (file:/usr/share/maven/lib/guice.jar) to method java.lang.ClassLoader.defineClass(java.lang.String,byte[],int,int,java.security.ProtectionDomain)
WARNING: Please consider reporting this to the maintainers of com.google.inject.internal.cglib.core.$ReflectUtils$1
WARNING: Use --illegal-access=warn to enable warnings of further illegal reflective access operations
WARNING: All illegal access operations will be denied in a future release"""
    output = ignore_groovy_errors(test_input)
    assert output == []


def test_ignore_groovy_errors__keep_non_groovy_messages():
    test_input = """'safety' is not recognized as an internal or external command, operable program or batch file."""
    output = ignore_groovy_errors(test_input)
    assert output == [test_input]


def test_ignore_groovy_errors__ignore_empty_messages():
    test_input = """            """
    output = ignore_groovy_errors(test_input)
    assert output == []
