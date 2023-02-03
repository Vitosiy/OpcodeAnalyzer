from typing import TextIO
from typing.io import IO


class ResultReader:
    def __init__(self):
        ...

    @staticmethod
    def read(path: str = '/var/www/html/vld_output.txt') -> TextIO:
        result = open(path, "r")
        return result
