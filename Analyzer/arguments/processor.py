from typing.io import IO
from Analyzer.signature_worker import SignatureWorker, SignatureFiles
from .parser import ScanMode, VulnerabilityType
from .vld.rebuilder import VldRebuilder


class ArgumentProcessorWrongVulnerabilityTypeError(Exception):
    pass


class ArgumentsProcessor:
    def __init__(self):
        ...

    @staticmethod
    def pick_signature_analyzer(vulnerability_type: str) -> SignatureWorker:
        if vulnerability_type == VulnerabilityType.SQLI.value:
            return SignatureWorker(SignatureFiles.SQLI.value)
        elif vulnerability_type == VulnerabilityType.RXSS.value:
            return SignatureWorker(SignatureFiles.RXSS.value)
        else:
            raise ArgumentProcessorWrongVulnerabilityTypeError(vulnerability_type)

    def _open_opcode_files(self, path: str) -> IO:
        try:
            result = open(path, "r")
            return result
        except FileNotFoundError as ex:
            #  Добавить логирование (опционально)
            raise

    def prepare_instruments(self, scan_mode: ScanMode, path: str) -> IO:
        if scan_mode == ScanMode.OPCODE_FILE.value:
            return self._open_opcode_files(path)
        if scan_mode == ScanMode.SCAN_DIR.value:
            rebuilder = VldRebuilder()
            rebuilder.rebuild(path)
