import opcodes_parser as op_parser
from Analyzer.arguments.processor import ArgumentsProcessor
from Analyzer.arguments.vld.result_reader import ResultReader
from Analyzer.arguments.vld.starter import VldStarter
from Analyzer.arguments.parser import ArgumentParser, ScanMode


# Scan patterns:
# -v sqli -s opcode_file -p /var/www/html/vld_output.txt

# opcode_file:
# -v sqli -s opcode_file -p /home/kali/OpcodeAnalyzer/Tests/SQL_Injections/Easy_Modal.txt
# -v sqli -s opcode_file -p /home/kali/OpcodeAnalyzer/Tests/SQL_Injections/Leagmanager.txt
# -v sqli -s opcode_file -p /home/kali/OpcodeAnalyzer/Tests/SQL_Injections/Answer_my_question.txt


# scan_dir:
#sql:
# -v sqli -s scan_dir -p /var/www/html/wp-content/plugins/easy-modal/classes/controller/admin/
# -v sqli -s scan_dir -p /var/www/html/wp-content/plugins/answer-my-question/
# -v sqli -s scan_dir -p /var/www/html/wp-content/plugins/product-catalog-8/
# -v sqli -s scan_dir -p /var/www/html/wp-content/plugins/leaguemanager/

# -v sqli -s scan_dir -p /var/www/html/wp-content/plugins/zephyr-project-manager/
# -v sqli -s scan_dir -p /var/www/html/wp-content/plugins/broken-link-repair/

#xss:
# -v sqli -s scan_dir -p /var/www/html/wp-content/plugins/wpschoolpress/


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

    print("\n coping data... \n")
    op_parser.parse_error_correction(result)
    print("\n opcode`s parsing... \n")
    EPs = op_parser.parse_file("../Logs/opcodes.txt")
    print("\n output entry points... \n")
    op_parser.print_entry_points(EPs)
    print("\n Start of opcode analysis: \n")
    signature_analyzer.init_analyze(EPs)
    result.close()
    print("\n End of opcode analysis. \n")


if __name__ == '__main__':
    main()
