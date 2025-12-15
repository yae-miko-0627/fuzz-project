"""简单占位测试，确保包导入正常。"""

def test_import_package():
    import mini_afl_py

    assert hasattr(mini_afl_py, "__version__")
