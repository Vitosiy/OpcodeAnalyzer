import argparse
import dataclasses
import enum


class VulnerabilityType(enum.Enum):
    RXSS = 'rxss'
    SQLI = 'sqli'


class ScanMode(enum.Enum):
    OPCODE_FILE = 'opcode_file'
    SCAN_DIR = 'scan_dir'


@dataclasses.dataclass
class Arguments:
    vulnerability_type: str
    scan_mode: ScanMode
    path: str


class ArgumentParser:
    def __init__(self):
        self._parser = argparse.ArgumentParser()
        self._initialize_parser()

    def _initialize_parser(self) -> None:
        self._parser.add_argument('-v', '--vuln_type', choices=('rxss', 'sqli'), type=str, help='Type of vulnerabilities sought')
        self._parser.add_argument('-s', '--scan_mode', type=str, help='Scan mode')
        self._parser.add_argument('-p', '--path', type=str, help='Path to directory/file')

    def parse(self) -> Arguments:
        args = self._parser.parse_args()

        result = Arguments(
            vulnerability_type=args.vuln_type,
            scan_mode=args.scan_mode,
            path=args.path,
        )

        return result

