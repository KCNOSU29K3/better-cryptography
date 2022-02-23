from setuptools import setup, find_packages

VERSION = "0.4.1"
DESCRIPTION = "A module for encryption and information security operations."
setup(
    name= "better cryptography",
    author = 'Wyatt Garrioch',
    author_email = "w.garrioch456@gmail.com",
    version = VERSION,
    description = DESCRIPTION,
    long_description = open("/home/eternal_blue/better_cryptography/README.md").read(),
    long_description_content_type="text/markdown",
    packages = find_packages(),
    install_requires = ['pycryptodome', "rsa", "cryptography"],
    keywords=["python", "encryption", "AES", "information security"],
    classifiers= [
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Education",
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux"
    ]
    
)