import os
import re
import time
from Scanner.arguments.vld.starter import VldStarter


class VldRebuilder:
    DEFAULT_VLD_PATH = '../VLD-0.18.0_modified_version/vld.c'

    def __init__(self, vld_path: str = DEFAULT_VLD_PATH):
        self._vld_path = vld_path
        self._starter = VldStarter()

    def _read_vld_file(self) -> str:
        return open(self._vld_path, 'r').read()

    def rebuild(self, scan_dir: str):
        vld_file = self._read_vld_file()
        new_vld_file = self._patch(scan_dir, vld_file)
        self._write_path(new_vld_file)
        self._clear_vld_output()
        self._recompile()

    def _recompile(self):
        self._starter.stop()
        os.system("sh ../Scripts/REBUILD_VLD.SH")

    def _write_path(self, new_data: str):
        with open(self._vld_path, 'w') as file:
            file.write(new_data)

    def _clear_vld_output(self):
        path = '/var/www/html/vld_output.txt'
        file = open(path, "w")
        file.close()


    @staticmethod
    def _patch(path_to_scan_dir: str, string_to_replace_in: str):
        new_data = re.sub(
            r"char ScanDir\[\] = .*",
            "char ScanDir[] = " + "\"" + path_to_scan_dir + "\";",
            string_to_replace_in
        )
        return new_data
