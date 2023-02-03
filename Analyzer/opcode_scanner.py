import opcodes_parser as op_parser
from Analyzer.arguments.processor import ArgumentsProcessor
from Analyzer.arguments.vld.result_reader import ResultReader
from Analyzer.arguments.vld.starter import VldStarter
from Analyzer.arguments.parser import ArgumentParser, ScanMode


# Scan patterns:
# -v sqli -s opcode_file -p /var/www/html/vld_output.txt

# opcode_file:
# -v sqli -s opcode_file -p /home/kali/OpcodeScanner/Logs/my_test_opcodes2.txt

# scan_dir:
# -v sqli -s scan_dir -p /var/www/html/wp-content/plugins/easy-modal/classes/controller/admin/
# -v sqli -s scan_dir -p /var/www/html/wp-content/plugins/answer-my-question/
# -v sqli -s scan_dir -p /var/www/html/wp-content/plugins/product-catalog-8/
# -v sqli -s scan_dir -p /var/www/html/wp-content/plugins/leaguemanager/

def main():
    argument_parser = ArgumentParser()
    arguments = argument_parser.parse()

    processor = ArgumentsProcessor()
    result = processor.prepare_instruments(arguments.scan_mode, arguments.path)
    signature_analyzer = processor.pick_signature_analyzer(arguments.vulnerability_type)

    if arguments.scan_mode == ScanMode.SCAN_DIR.value:
        starter = VldStarter()
        starter.start()
        result_reader = ResultReader()
        result = result_reader.read()

    print("\n Start of opcode analysis \n")
    op_parser.parse_error_correction(result)
    EPs = op_parser.parse_file("../Logs/opcodes.txt")
    op_parser.print_entry_points(EPs)
    signature_analyzer.init_analyze(EPs)
    result.close()
    print("\n End of opcode analysis \n")


if __name__ == '__main__':
    main()
