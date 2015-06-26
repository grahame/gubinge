from setuptools import setup, find_packages

dev_requires = ['flake8', 'nose']
install_requires = []

setup(
    author="Grahame Bowland",
    author_email="grahame@angrygoats.net",
    description="ssh-agent proxy",
    long_description="lock down and control your ssh-agent",
    license="GPL3",
    keywords="openssh ssh",
    url="https://github.com/grahame/gubinge",
    name="gubinge",
    version="0.0.1",
    packages=find_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests"]),
    extras_require={
        'dev': dev_requires
    },
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'gubinge=gubinge.cli:main',
        ],
    }
)
