import argparse
from .proxy import proxy


def main():
    parser = argparse.ArgumentParser()
    args = parser.parse_args()  # noqa
    proxy()
