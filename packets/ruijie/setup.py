from distutils.core import setup, Extension

module1 = Extension('extra', sources = ['extra.c', 'extra_data.c', 'extra_md5.c', 'extra_whirlpool.c', 'extra_sha1.c', 'extra_ripemd128.c', 'extra_tiger.c'])
setup(name = 'extra', ext_modules = [module1])
