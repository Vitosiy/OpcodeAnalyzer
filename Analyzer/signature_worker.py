import re
import json
import copy
import opcodes
import opcodes_parser as op_parser
from enum import Enum

predefined_variables = ['_GET', '_POST', '_COOKIE', '_REQUEST']
opcode_line_pattern = re.compile(r"[\d]{1,10}\*{0,1} * [\d]{0,10} * E{0,1} >{0,1} >{0,1} * ([A-Z]{1,32}_{0,1}){0,10} *")
split_slashes = re.compile(r"[%5C,%2F]")
exclude_operations = ['EXT_STMT', 'JMP', 'JMPZ']


class SignatureFiles(Enum):
    SQLI = "./vulnSignatures/sql.txt"
    RXSS = "./vulnSignatures/xss.txt"


class CalledFunction:
    def __init__(self, name: str = '', operands=None, ret_value: str = ''):
        if operands is None:
            operands = []
        self.name = name
        self.operands = operands
        self.ret_value = ret_value
        self.func_vuln_score = opcodes.VarScore.UNDEFINED


class SignatureWorker:

    def __init__(self, signature_file):
        self.start_point = []
        self.signature_list = []
        self.EPs = {}
        self.global_call_stack = {}
        opcode_file = open(signature_file, "r")
        line = opcode_file.readline()
        index = 0

        while line:

            if "start_point:" in line:
                line = opcode_file.readline()

                while "signature:" not in line and '\n' != line:
                    # if re.search(opcode_line_pattern, line):
                    opcode = self._parse_signature_opcode_line(line, index)
                    index += 1
                    self.start_point.append(opcode)
                    line = opcode_file.readline()

            if "signature:" in line:
                signature = opcodes.VulnSignature()

                line = opcode_file.readline().replace('\n', '')
                signature.name = line.split(' ')[1]

                line = opcode_file.readline().replace('\n', '')
                signature.danger_level = line.split(' ')[1]

                line = opcode_file.readline().replace('\n', '')
                signature.opcodes_number = line.split(' ')[1]

                line = opcode_file.readline().replace('\n', '')
                if "vuln_function:" in line:
                    for i in range(0, int(signature.opcodes_number)):
                        line = opcode_file.readline()

                        # if re.search(opcode_line_pattern, line):
                        opcode = self._parse_signature_opcode_line(line, i)
                        signature.signature.append(opcode)

                line = opcode_file.readline().replace('\n', '')
                if "def_functions:" in line:
                    line = opcode_file.readline()

                    # if re.search(opcode_line_pattern, line):
                    opcode = self._parse_signature_opcode_line(line, 0)
                    signature.def_functions.append(opcode)

                self.signature_list.append(signature)

            line = opcode_file.readline()

    def init_analyze(self, EPs):
        self.EPs = EPs

        for item in EPs:
            file_eps = EPs.get(item)
            for item_eps in file_eps:
                EP = file_eps.get(item_eps)
                self.global_call_stack[EP.function_name] = CalledFunction(EP.function_name)
                result_log = self._analyze(EP)
                self.global_call_stack.pop(EP.function_name)
                if result_log and result_log != "[]":
                    print("\n-----------------{}-----------------".format(EP.function_name))
                    print("-------------------START-------------------")
                    parsed = json.loads(result_log)
                    dumped = json.dumps(parsed, indent=2)
                    print(dumped)
                    print("\n--------------------END--------------------\n")

    def _parse_signature_opcode_line(self, opcode_line, index=0):
        line = opcode_line.split('  ')
        line = [x.replace('>', '').replace('\n', '').replace('\'', '').strip() for x in line]
        line = [x for x in line if x != 'E' and x != 'global']
        line_items = []

        for l in line:
            if l != '':
                line_items.append(l)

        if len(line_items) < 2:
            print("parse_opcode_line: Error, unexpected number of items in a line.")
            print("line:", opcode_line)
        else:  # if len(line_items) >= 2
            if line_items[0].isdigit():  # оставляем лишь линейные индексы (ветки и циклы игнорируем)
                line_items.pop(0)

        if len(line_items) > 2 and line_items[1].isdigit():
            line_items.pop(2)  # избавляемся от значений из колонки ext

        if len(line_items) not in [2,
                                   3]:  # должны остаться значения из колонок индекс, опкод, возвращаемое значение и операнды
            print("parse_opcode_line: Error, unexpected number of items in a line.")
            print("line:", opcode_line)

        opcode = opcodes.Opcode()
        opcode.index = index

        if len(line_items) < 2:
            return opcode

        opcode.operation = line_items[0]
        if len(line_items) == 2:  # определяем какой колонке принадлежит 3-й элемент - возвращаемое значение или операнд
            if line_items[1] == line[-1]:
                opcode.operands = line_items[1].split(', ')
            else:
                opcode.ret_value = line_items[1]
        elif len(line_items) == 3:
            opcode.ret_value = line_items[1]
            opcode.operands = line_items[2].split(', ')

        for i in range(0, len(opcode.operands)):
            if opcode.operands[i] == '*def_var*':
                opcode.operands[i] = predefined_variables

        return opcode

    def _print_var_status(self, var, vuln_function_name, op_id, EP, statement):

        var_type = {
            0: 'UNDEFINED',
            1: 'COMPILED',
            2: 'TEMPORARY',
            3: 'RETURNED',
        }

        if var.var_score == opcodes.VarScore.UNSECURE:
            return "{\"STATUS\":" + "\"UNSECURE: {} variable {} used or returned without a protective function\",".format(
                var_type.get(var.var_type.value), var.ID) + \
                   "\"FILE_NAME\":\"{}\",".format(EP.filename.strip()) + \
                   "\"FUNCTION_NAME\":\"{}\",".format(EP.function_name) + \
                   "\"STATEMENT_NUMBER\":{}".format(statement.index) + '}'
        if var.var_score == opcodes.VarScore.DANGEROUS:
            return "{\"STATUS\":" + "\"DANGEROUS: {} variable {} used in a dangerous function: {}\",".format(
                var_type.get(var.var_type.value), var.ID, vuln_function_name) + \
                   "\"FILE_NAME\":\"{}\",".format(EP.filename.strip()) + \
                   "\"FUNCTION_NAME\":\"{}\",".format(EP.function_name) + \
                   "\"STATEMENT_NUMBER\":{},".format(statement.index) + \
                   "\"OPCODE_NUMBER\":{}".format(op_id) + '}'

    def _find_function(self, func_name, orig_EP):

        orig_file_EPs = self.EPs.get(orig_EP.filename)
        for item_eps in orig_file_EPs:
            if item_eps == func_name:
                return orig_file_EPs.get(item_eps)

        for file_item in self.EPs:
            file_eps = self.EPs.get(file_item)
            for item_eps in file_eps:
                if item_eps == func_name:
                    return file_eps.get(item_eps)

        return False

    def _analyze(self, EP, vuln_var=None):

        if EP.analyze_result != "" and vuln_var is None:
            return EP.analyze_result

        return_status_log = "["
        statements = op_parser.get_statements_from_opcodes(EP.opcodes)

        detect_start_point = 1 if not vuln_var is None else 0

        temporary_vars = {}
        returned_vars = {}
        compiled_vars = {}
        for var in EP.compiled_variables:
            if detect_start_point and var.ID == vuln_var.ID:
                compiled_vars[var.ID] = vuln_var
            else:
                compiled_vars[var.ID] = copy.copy(var)

        fcall_flag = 0
        fcall_count = 0
        fcall_buffer = []

        def send_0_flag_case(call_func, opcode, vars_map, operand_number=0):
            call_func.operands.append(opcode.operands[operand_number])
            var = vars_map.get(opcode.operands[operand_number])
            if var and var.var_score == opcodes.VarScore.UNSECURE and \
                    self.global_call_stack.get(call_func.name) is None:
                target_EP = self._find_function(call_func.name, EP)
                sended_var = copy.copy(var)
                sended_var.ID = "!{}".format(len(call_func.operands) - 1)
                if target_EP:

                    self.global_call_stack[target_EP.function_name] = CalledFunction(target_EP.function_name)
                    tmp_return_log = self._analyze(target_EP, sended_var)
                    self.global_call_stack.pop(target_EP.function_name)

                    if tmp_return_log and tmp_return_log != "[]":
                        call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                        var.var_score = opcodes.VarScore.DANGEROUS
                        return "[" + self._print_var_status(var, fcall_buffer[fcall_count - 1].name, opcode.index, EP,
                                                            statement) + ',' + tmp_return_log + "]"

        def send_safe_flag_case(call_func, opcode, vars_map, operand_number=0):
            call_func.operands.append(opcode.operands[operand_number])
            var = vars_map.get(opcode.operands[operand_number])
            if var:
                var.var_score = opcodes.VarScore.SECURE

        def send_danger_flag_case(call_func, opcode, vars_map, operand_number=0):
            call_func.operands.append(opcode.operands[operand_number])
            var = vars_map.get(opcode.operands[operand_number])
            if var and var.var_score == opcodes.VarScore.UNSECURE:
                var.var_score = opcodes.VarScore.DANGEROUS
                vuln_func_name = fcall_buffer[0].name
                for func in fcall_buffer[1:]:
                    vuln_func_name += "->" + func.name
                return self._print_var_status(var, vuln_func_name, opcode.index, EP,
                                              statement)

        for statement in statements:
            # ОЧИСТКА temporary_vars для каждого statement
            temporary_vars.clear()

            # АНАЛИЗ ОПКОДОВ
            for opcode in statement.opcodes:

                if opcode.operation in exclude_operations:
                    continue

                # Детектируем точку входа и запоминаем временную переменную из результата
                if opcode.operation == self.start_point[0].operation and \
                        opcode.operands[0] in self.start_point[0].operands[0]:
                    detect_start_point += 1

                    flag = 0
                    if re.match(r"~\d", opcode.ret_value):
                        var = temporary_vars.get(opcode.ret_value)
                        if var:
                            var.value = opcode.operands
                            var.var_score = opcodes.VarScore.UNSECURE
                            flag = 1
                        if flag == 0:
                            var = opcodes.Variable()
                            var.ID = opcode.ret_value
                            var.var_type = opcodes.VarType.TEMPORARY
                            var.value = opcode.operands
                            var.var_score = opcodes.VarScore.UNSECURE
                            temporary_vars[var.ID] = var
                    if re.match(r"\$\d", opcode.ret_value):
                        var = returned_vars.get(opcode.ret_value)
                        if var:
                            var.value = opcode.operands
                            var.var_score = opcodes.VarScore.UNSECURE
                            flag = 1
                        if flag == 0:
                            var = opcodes.Variable()
                            var.ID = opcode.ret_value
                            var.var_type = opcodes.VarType.TEMPORARY
                            var.value = opcode.operands
                            var.var_score = opcodes.VarScore.UNSECURE
                            returned_vars[var.ID] = var

                    continue

                detect_signature = 0
                for signature in self.signature_list:
                    if signature.def_functions[0].operation in opcode.operation \
                            or signature.signature[0].operation in opcode.operation:

                        if "INIT_" in opcode.operation and "CALL" in opcode.operation:

                            # если мы во вложенном fcall, и уже стоит флаг fcall_flag = 2
                            # и встретилась защитная, то мы ставим 1 (защитная функция вложена в опасную)
                            # запомниаем имя функции в буфер
                            for def_func in signature.def_functions[0].operands:
                                if def_func in opcode.operands:
                                    fcall_count += 1
                                    fcall_flag = 1
                                    call_func = CalledFunction(def_func)
                                    call_func.func_vuln_score = opcodes.VarScore.SECURE
                                    fcall_buffer.append(call_func)
                                    detect_signature = 1
                                    break

                            # если мы во вложенном fcall, и уже стоит флаг fcall_flag = 1 и
                            # встретилась опасная, то мы НЕ ставим 2 (опасная функция вложена в защитную)
                            # запомниаем имя функции в буфер
                            if signature.signature[0].operands[len(signature.signature[0].operands) - 1] in \
                                    opcode.operands and fcall_flag != 1:
                                fcall_count += 1
                                fcall_flag = 2
                                call_func = CalledFunction(
                                    signature.signature[0].operands[len(signature.signature[0].operands) - 1])
                                fcall_buffer.append(call_func)
                                detect_signature = 1
                                break

                        # Если видим операцию ECHO, то помечаем назащищенные переменные как опасные и выводим предупреждение
                        # Все варианты:
                        # ECHO    ~1
                        # ECHO    !1
                        # ECHO    $1
                        # ECHO    "string"
                        elif signature.signature[
                            0].operation == opcode.operation:  # На данный момент таких кодов операций только один: ECHO
                            for tv in temporary_vars:
                                var = temporary_vars.get(tv)
                                if var.ID in opcode.operands and var.var_score == opcodes.VarScore.UNSECURE:
                                    var.var_score = opcodes.VarScore.DANGEROUS
                                    return_status_log += ',' if return_status_log != "[" else ''
                                    return_status_log += self._print_var_status(var, fcall_buffer[
                                        fcall_count - 1].name, opcode.index, EP,
                                                                                statement)
                            for cv in compiled_vars:
                                var = temporary_vars.get(cv)
                                if var.ID in opcode.operands and var.var_score == opcodes.VarScore.UNSECURE:
                                    var.var_score = opcodes.VarScore.DANGEROUS
                                    return_status_log += ',' if return_status_log != "[" else ''
                                    return_status_log += self._print_var_status(var, fcall_buffer[
                                        fcall_count - 1].name, opcode.index, EP,
                                                                                statement)
                            for rv in returned_vars:
                                var = returned_vars.get(rv)
                                if var.ID in opcode.operands and var.var_score == opcodes.VarScore.UNSECURE:
                                    var.var_score = opcodes.VarScore.DANGEROUS
                                    return_status_log += ',' if return_status_log != "[" else ''
                                    return_status_log += self._print_var_status(var, fcall_buffer[
                                        fcall_count - 1].name, opcode.index, EP,
                                                                                statement)
                            detect_signature = 1
                            break

                if detect_signature:
                    continue

                if "INIT_" in opcode.operation and "CALL" in opcode.operation:
                    if len(opcode.operands) > 0:
                        fcall_count += 1
                        func_name = re.split(split_slashes, opcode.operands[len(opcode.operands) - 1])
                        func_name = [x for x in func_name if x != '']
                        call_func = CalledFunction(func_name[len(func_name) - 1])
                        fcall_buffer.append(call_func)
                    continue

                if "RETURN" in opcode.operation:
                    if len(opcode.operands) > 0:
                        operand_var = temporary_vars.get(opcode.operands[0]) or returned_vars.get(
                            opcode.operands[0]) or compiled_vars.get(opcode.operands[0])

                        if operand_var and \
                                (operand_var.var_score == opcodes.VarScore.UNSECURE or
                                 operand_var.var_score == opcodes.VarScore.DANGEROUS):
                            return_status_log += ',' if return_status_log != "[" else ''

                            return_status_log += self._print_var_status(operand_var,
                                                                        fcall_buffer[fcall_count - 1].name if len(
                                                                            fcall_buffer) > 0
                                                                        else EP.function_name,
                                                                        opcode.index, EP, statement)
                    continue

                # Если видим операцию ASSIGN, то в compiled_vars ищем переменную из первого операнда
                # и записываем в нее переменную из второго операнда. Возможные варианты:
                # ASSIGN !1, ~2
                # ASSIGN !1, $2
                # ASSIGN !1, !2
                if "ASSIGN" in opcode.operation:
                    if "QM_" in opcode.operation:
                        if re.match(r"!\d", opcode.ret_value):
                            var = compiled_vars.get(opcode.ret_value)
                            if var:
                                operand_var = temporary_vars.get(opcode.operands[0]) or returned_vars.get(
                                    opcode.operands[0]) or compiled_vars.get(opcode.operands[0])
                                var.var_score = operand_var.var_score if operand_var else opcodes.VarScore.UNDEFINED
                                var.value = opcode.operands[0]
                        elif re.match(r"~\d", opcode.ret_value):
                            var = temporary_vars.get(opcode.ret_value)
                            if var:
                                operand_var = temporary_vars.get(opcode.operands[0]) or returned_vars.get(
                                    opcode.operands[0]) or compiled_vars.get(opcode.operands[0])
                                var.var_score = operand_var.var_score if operand_var else opcodes.VarScore.UNDEFINED
                                var.value = opcode.operands[0]
                        elif re.match(r"\$\d", opcode.ret_value):
                            var = returned_vars.get(opcode.ret_value)
                            if var:
                                operand_var = temporary_vars.get(opcode.operands[0]) or returned_vars.get(
                                    opcode.operands[0]) or compiled_vars.get(opcode.operands[0])
                                var.var_score = operand_var.var_score if operand_var else opcodes.VarScore.UNDEFINED
                                var.value = opcode.operands[0]
                    elif len(opcode.operands) > 1:
                        if re.match(r"!\d", opcode.operands[0]):
                            var = compiled_vars.get(opcode.operands[0])
                            if var:
                                operand_var = temporary_vars.get(opcode.operands[1]) or returned_vars.get(
                                    opcode.operands[1]) or compiled_vars.get(opcode.operands[1])
                                var.var_score = operand_var.var_score if operand_var else opcodes.VarScore.UNDEFINED
                                var.value = opcode.operands[1]
                        elif re.match(r"~\d", opcode.operands[0]):
                            var = temporary_vars.get(opcode.operands[0])
                            if var:
                                operand_var = temporary_vars.get(opcode.operands[1]) or returned_vars.get(
                                    opcode.operands[1]) or compiled_vars.get(opcode.operands[1])
                                var.var_score = operand_var.var_score if operand_var else opcodes.VarScore.UNDEFINED
                                var.value = opcode.operands[1]
                        elif re.match(r"\$\d", opcode.operands[0]):
                            var = returned_vars.get(opcode.operands[0])
                            if var:
                                operand_var = temporary_vars.get(opcode.operands[1]) or returned_vars.get(
                                    opcode.operands[1]) or compiled_vars.get(opcode.operands[1])
                                var.var_score = operand_var.var_score if operand_var else opcodes.VarScore.UNDEFINED
                                var.value = opcode.operands[1]
                    continue

                # Если видим операцию CONCAT, для временных переменных: либо записываем операнды в существующую переменную,
                # либо добавляем новую переменную, для скомпилированных: записываем операнды в существующую переменную.
                # CONCAT     ~1      ~2, ~3 (любые комбинации пар переменных ~, $, ! и строк "")
                # CONCAT     !1      ~2, ~3 (любые комбинации пар переменных ~, $, ! и строк "")
                if "CONCAT" in opcode.operation and len(opcode.operands) > 0:  # CONCAT, FAST_CONCAT

                    operand_var1 = temporary_vars.get(opcode.operands[0]) or returned_vars.get(
                        opcode.operands[0]) or compiled_vars.get(opcode.operands[0])

                    if len(opcode.operands) > 1:
                        operand_var2 = temporary_vars.get(opcode.operands[1]) or returned_vars.get(
                            opcode.operands[1]) or compiled_vars.get(opcode.operands[1])
                    else:
                        operand_var2 = False

                    var_score = opcodes.VarScore.UNDEFINED
                    if operand_var1 and operand_var2:
                        var_score = operand_var1.var_score if operand_var1.var_score.value > operand_var2.var_score.value else operand_var2.var_score
                    elif operand_var2:
                        var_score = operand_var2.var_score
                    elif operand_var1:
                        var_score = operand_var1.var_score

                    if re.match(r"~\d", opcode.ret_value):
                        flag = 0
                        var = temporary_vars.get(opcode.ret_value)
                        if var:
                            var.value = opcode.operands
                            if var.var_score != opcodes.VarScore.DANGEROUS and var.var_score != opcodes.VarScore.UNSECURE:
                                var.var_score = var_score
                            flag = 1
                        if flag == 0:
                            var = opcodes.Variable()
                            var.ID = opcode.ret_value
                            var.var_type = opcodes.VarType.TEMPORARY
                            var.value = opcode.operands
                            var.var_score = var_score
                            temporary_vars[var.ID] = var
                    if re.match(r"\$\d", opcode.ret_value):
                        flag = 0
                        var = returned_vars.get(opcode.ret_value)
                        if var:
                            var.value = opcode.operands
                            if var.var_score != opcodes.VarScore.DANGEROUS and var.var_score != opcodes.VarScore.UNSECURE:
                                var.var_score = var_score
                            flag = 1
                        if flag == 0:
                            var = opcodes.Variable()
                            var.ID = opcode.ret_value
                            var.var_type = opcodes.VarType.RETURNED
                            var.value = opcode.operands
                            var.var_score = var_score
                            temporary_vars[var.ID] = var
                    if re.match(r"!\d", opcode.ret_value):
                        var = compiled_vars.get(opcode.ret_value)
                        if var:
                            var.value = opcode.operands
                            if var.var_score != opcodes.VarScore.DANGEROUS and var.var_score != opcodes.VarScore.UNSECURE:
                                var.var_score = var_score

                    continue

                if "CAST" in opcode.operation and len(opcode.operands) > 0:
                    operand_var = temporary_vars.get(opcode.operands[0]) or returned_vars.get(
                        opcode.operands[0]) or compiled_vars.get(opcode.operands[0])

                    var_score = opcodes.VarScore.SECURE
                    # if operand_var:
                    #     var_score = operand_var.var_score

                    if re.match(r"~\d", opcode.ret_value):
                        flag = 0
                        var = temporary_vars.get(opcode.ret_value)
                        if var:
                            var.value = opcode.operands
                            var.var_score = var_score
                            flag = 1
                        if flag == 0:
                            var = opcodes.Variable()
                            var.ID = opcode.ret_value
                            var.var_type = opcodes.VarType.TEMPORARY
                            var.value = opcode.operands
                            var.var_score = var_score
                            temporary_vars[var.ID] = var
                    if re.match(r"\$\d", opcode.ret_value):
                        flag = 0
                        var = returned_vars.get(opcode.ret_value)
                        if var:
                            var.value = opcode.operands
                            var.var_score = var_score
                            flag = 1
                        if flag == 0:
                            var = opcodes.Variable()
                            var.ID = opcode.ret_value
                            var.var_type = opcodes.VarType.RETURNED
                            var.value = opcode.operands
                            var.var_score = var_score
                            temporary_vars[var.ID] = var
                    if re.match(r"!\d", opcode.ret_value):
                        var = compiled_vars.get(opcode.ret_value)
                        if var:
                            var.value = opcode.operands
                            var.var_score = var_score

                    continue

                # Если видим операцию FETCH_DIM_R
                # Все варианты:
                # FETCH_DIM_R    ~1      ~2, ~3 (любые комбинации пар переменных ~, $, ! и строк "")
                # FETCH_DIM_R    !1      ~2, ~3 (любые комбинации пар переменных ~, $, ! и строк "")
                # FETCH_DIM_R    $1      ~2, ~3 (любые комбинации пар переменных ~, $, ! и строк "")
                if opcode.operation == "FETCH_DIM_R":
                    operand_var = temporary_vars.get(opcode.operands[0]) or returned_vars.get(
                        opcode.operands[0]) or compiled_vars.get(opcode.operands[0])

                    if re.match(r"~\d", opcode.ret_value):
                        flag = 0
                        var = temporary_vars.get(opcode.ret_value)
                        if var:
                            var.value = opcode.operands
                            var.var_score = operand_var.var_score if operand_var else opcodes.VarScore.UNDEFINED
                            flag = 1
                        if flag == 0:
                            var = opcodes.Variable()
                            var.ID = opcode.ret_value
                            var.var_type = opcodes.VarType.TEMPORARY
                            var.var_score = operand_var.var_score if operand_var else opcodes.VarScore.UNDEFINED
                            var.value = opcode.operands
                            temporary_vars[var.ID] = var
                    if re.match(r"!\d", opcode.ret_value):
                        var = compiled_vars.get(opcode.ret_value)
                        if var:
                            var.value = opcode.operands
                            var.var_score = operand_var.var_score if operand_var else opcodes.VarScore.UNDEFINED
                    if re.match(r"\$\d", opcode.ret_value):
                        flag = 0
                        var = returned_vars.get(opcode.ret_value)
                        if var:
                            var.value = opcode.operands
                            var.var_score = operand_var.var_score if operand_var else opcodes.VarScore.UNDEFINED
                            flag = 1
                        if flag == 0:
                            var = opcodes.Variable()
                            var.ID = opcode.ret_value
                            var.var_type = opcodes.VarType.RETURNED
                            var.value = opcode.operands
                            var.var_score = operand_var.var_score if operand_var else opcodes.VarScore.UNDEFINED
                            returned_vars[var.ID] = var

                    continue

                # Схема анализа вызова функций:
                # INIT_FCALL - выставить флаг (1 - защитная, 2 - опасная)
                # SEND_VAR - проверить флаг
                # SEND_VAL - проверить флаг
                # DO_FCALL - снять флаг (0 - не интересует)

                # Пример вложенного FCALL
                # INIT_FCALL        'htmlspecialchars'
                # INIT_FCALL        'strip_tags'
                # SEND_VAR          !3
                # DO_FCALL  $27
                # SEND_VAR          $27
                # DO_FCALL

                if fcall_count > 0:
                    if opcode.operation == "DO_FCALL":
                        fcall_count -= 1

                        if fcall_buffer[fcall_count].func_vuln_score == opcodes.VarScore.UNDEFINED and \
                                fcall_buffer[fcall_count].name != EP.function_name and \
                                self.global_call_stack.get(fcall_buffer[fcall_count].name) is None:

                            target_EP = self._find_function(fcall_buffer[fcall_count].name, EP)
                            if target_EP:

                                # print("DO_FCALL: {}".format(target_EP.function_name))

                                self.global_call_stack[target_EP.function_name] = CalledFunction(
                                    target_EP.function_name)
                                tmp_return_log = self._analyze(target_EP)
                                self.global_call_stack.pop(target_EP.function_name)

                                if tmp_return_log and tmp_return_log != "[]":
                                    fcall_buffer[fcall_count].func_vuln_score = opcodes.VarScore.UNSECURE

                        if fcall_count >= 0 and len(fcall_buffer) > 0:
                            # Для лога надо запомнить название вызываемой функции,
                            # поэтому запишем ее в операнды (там свободно)
                            opcode.operands.append(fcall_buffer[fcall_count].name)

                        if re.match(r"\$\d", opcode.ret_value):
                            # фиксируем возвращаемую переменную $
                            # (накопленные в буфер значения операндов INIT_FCALL, SEND_VAL, SEND_VAR)
                            var = returned_vars.get(opcode.ret_value)
                            if var:
                                var.var_score = fcall_buffer[fcall_count].func_vuln_score
                                var.value = opcode.operands
                            else:
                                var = opcodes.Variable()
                                var.ID = opcode.ret_value
                                var.var_type = opcodes.VarType.RETURNED
                                var.value = opcode.operands
                                var.var_score = fcall_buffer[fcall_count].func_vuln_score
                                returned_vars[var.ID] = var

                        if fcall_count == 0:  # если это самый внешний fcall,
                            fcall_flag = 0  # то снимаем флаг fcall_flag
                            fcall_buffer.clear()
                        else:
                            fcall_buffer.pop()

                        continue

                    # SEND_VAR   !1
                    # SEND_VAR   $1
                    if "SEND_VAR" in opcode.operation and len(opcode.operands) > 0:
                        call_func = fcall_buffer[len(fcall_buffer) - 1]
                        if fcall_flag == 0:
                            if re.match(r"~\d", opcode.operands[0]):
                                tmp_return_log = send_0_flag_case(call_func, opcode, temporary_vars)
                                if tmp_return_log:
                                    call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                                    return_status_log += ',' if return_status_log != "[" else ''
                                    return_status_log += tmp_return_log
                            if re.match(r"!\d", opcode.operands[0]):
                                tmp_return_log = send_0_flag_case(call_func, opcode, compiled_vars)
                                if tmp_return_log:
                                    call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                                    return_status_log += ',' if return_status_log != "[" else ''
                                    return_status_log += tmp_return_log
                            if re.match(r"\$\d", opcode.operands[0]):
                                tmp_return_log = send_0_flag_case(call_func, opcode, returned_vars)
                                if tmp_return_log:
                                    call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                                    return_status_log += ',' if return_status_log != "[" else ''
                                    return_status_log += tmp_return_log
                        if fcall_flag == 1:
                            if re.match(r"!\d", opcode.operands[0]):
                                send_safe_flag_case(call_func, opcode, compiled_vars)
                            if re.match(r"~\d", opcode.operands[0]):
                                send_safe_flag_case(call_func, opcode, temporary_vars)
                            if re.match(r"\$\d", opcode.operands[0]):
                                send_safe_flag_case(call_func, opcode, returned_vars)
                        if fcall_flag == 2:
                            if re.match(r"!\d", opcode.operands[0]):
                                tmp_return_log = send_danger_flag_case(call_func, opcode, compiled_vars)
                                if tmp_return_log:
                                    call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                                    return_status_log += ',' if return_status_log != "[" else ''
                                    return_status_log += tmp_return_log
                            if re.match(r"~\d", opcode.operands[0]):
                                tmp_return_log = send_danger_flag_case(call_func, opcode, temporary_vars)
                                if tmp_return_log:
                                    call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                                    return_status_log += ',' if return_status_log != "[" else ''
                                    return_status_log += tmp_return_log
                            if re.match(r"\$\d", opcode.operands[0]):
                                tmp_return_log = send_danger_flag_case(call_func, opcode, returned_vars)
                                if tmp_return_log:
                                    call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                                    return_status_log += ',' if return_status_log != "[" else ''
                                    return_status_log += tmp_return_log
                        continue

                    # SEND_VAL   'string'
                    # SEND_VAL   int
                    if "SEND_VAL" in opcode.operation and len(opcode.operands) > 0:
                        call_func = fcall_buffer[len(fcall_buffer) - 1]

                        if fcall_flag == 0:
                            if re.match(r"~\d", opcode.operands[0]):
                                tmp_return_log = send_0_flag_case(call_func, opcode, temporary_vars)
                                if tmp_return_log:
                                    call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                                    return_status_log += ',' if return_status_log != "[" else ''
                                    return_status_log += tmp_return_log
                            if re.match(r"!\d", opcode.operands[0]):
                                tmp_return_log = send_0_flag_case(call_func, opcode, compiled_vars)
                                if tmp_return_log:
                                    call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                                    return_status_log += ',' if return_status_log != "[" else ''
                                    return_status_log += tmp_return_log
                            if re.match(r"\$\d", opcode.operands[0]):
                                tmp_return_log = send_0_flag_case(call_func, opcode, returned_vars)
                                if tmp_return_log:
                                    call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                                    return_status_log += ',' if return_status_log != "[" else ''
                                    return_status_log += tmp_return_log
                        if fcall_flag == 1:
                            call_func.operands.append(opcode.operands[0])
                            if re.match(r"~\d", opcode.operands[0]):
                                for tv in temporary_vars:
                                    if tv == opcode.operands[0]:
                                        var = temporary_vars.get(tv)
                                        var.var_score = opcodes.VarScore.SECURE
                            if re.match(r"!\d", opcode.operands[0]):
                                for tv in compiled_vars:
                                    if tv == opcode.operands[0]:
                                        var = compiled_vars.get(tv)
                                        var.var_score = opcodes.VarScore.SECURE
                            if re.match(r"\$\d", opcode.operands[0]):
                                for tv in returned_vars:
                                    if tv == opcode.operands[0]:
                                        var = returned_vars.get(tv)
                                        var.var_score = opcodes.VarScore.SECURE
                        if fcall_flag == 2:
                            call_func.operands.append(opcode.operands[0])
                            if re.match(r"~\d", opcode.operands[0]):
                                for tv in temporary_vars:
                                    var = temporary_vars.get(tv)
                                    if var.ID == opcode.operands[0] and var.var_score == opcodes.VarScore.UNSECURE:
                                        var.var_score = opcodes.VarScore.DANGEROUS
                                        call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                                        return_status_log += ',' if return_status_log != "[" else ''
                                        return_status_log += self._print_var_status(var, fcall_buffer[
                                            fcall_count - 1].name,
                                                                                    opcode.index, EP,
                                                                                    statement)
                            if re.match(r"!\d", opcode.operands[0]):
                                for tv in compiled_vars:
                                    var = compiled_vars.get(tv)
                                    if var.ID == opcode.operands[0] and var.var_score == opcodes.VarScore.UNSECURE:
                                        var.var_score = opcodes.VarScore.DANGEROUS
                                        call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                                        return_status_log += ',' if return_status_log != "[" else ''
                                        return_status_log += self._print_var_status(var, fcall_buffer[
                                            fcall_count - 1].name,
                                                                                    opcode.index, EP,
                                                                                    statement)
                            if re.match(r"\$\d", opcode.operands[0]):
                                for tv in returned_vars:
                                    var = returned_vars.get(tv)
                                    if var.ID == opcode.operands[0] and var.var_score == opcodes.VarScore.UNSECURE:
                                        var.var_score = opcodes.VarScore.DANGEROUS
                                        call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                                        return_status_log += ',' if return_status_log != "[" else ''
                                        return_status_log += self._print_var_status(var, fcall_buffer[
                                            fcall_count - 1].name,
                                                                                    opcode.index, EP,
                                                                                    statement)
                        continue

                    # ROPE_ADD   ~3      ~3, !0
                    if ("ROPE_ADD" in opcode.operation or "ROPE_END" in opcode.operation) \
                            and len(opcode.operands) > 1:
                        call_func = fcall_buffer[len(fcall_buffer) - 1]

                        if fcall_flag == 0:
                            if re.match(r"~\d", opcode.operands[1]):
                                tmp_return_log = send_0_flag_case(call_func, opcode, temporary_vars, 1)
                                if tmp_return_log:
                                    call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                                    return_status_log += ',' if return_status_log != "[" else ''
                                    return_status_log += tmp_return_log
                            if re.match(r"!\d", opcode.operands[1]):
                                tmp_return_log = send_0_flag_case(call_func, opcode, compiled_vars, 1)
                                if tmp_return_log:
                                    call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                                    return_status_log += ',' if return_status_log != "[" else ''
                                    return_status_log += tmp_return_log
                            if re.match(r"\$\d", opcode.operands[1]):
                                tmp_return_log = send_0_flag_case(call_func, opcode, returned_vars, 1)
                                if tmp_return_log:
                                    call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                                    return_status_log += ',' if return_status_log != "[" else ''
                                    return_status_log += tmp_return_log
                        if fcall_flag == 1:
                            if re.match(r"!\d", opcode.operands[1]):
                                send_safe_flag_case(call_func, opcode, compiled_vars, 1)
                            if re.match(r"\$\d", opcode.operands[1]):
                                send_safe_flag_case(call_func, opcode, returned_vars, 1)
                            if re.match(r"~\d", opcode.operands[1]):
                                send_safe_flag_case(call_func, opcode, temporary_vars, 1)
                        if fcall_flag == 2:
                            if re.match(r"!\d", opcode.operands[1]):
                                tmp_return_log = send_danger_flag_case(call_func, opcode, compiled_vars, 1)
                                if tmp_return_log:
                                    call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                                    return_status_log += ',' if return_status_log != "[" else ''
                                    return_status_log += tmp_return_log
                            if re.match(r"\$\d", opcode.operands[1]):
                                tmp_return_log = send_danger_flag_case(call_func, opcode, returned_vars, 1)
                                if tmp_return_log:
                                    call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                                    return_status_log += ',' if return_status_log != "[" else ''
                                    return_status_log += tmp_return_log
                            if re.match(r"~\d", opcode.operands[1]):
                                tmp_return_log = send_danger_flag_case(call_func, opcode, temporary_vars, 1)
                                if tmp_return_log:
                                    call_func.func_vuln_score = opcodes.VarScore.DANGEROUS
                                    return_status_log += ',' if return_status_log != "[" else ''
                                    return_status_log += tmp_return_log
                        continue
            #
            # for item in temporary_vars:
            #     var = temporary_vars.get(item)
            #     if var.var_score == opcodes.VarScore.UNSECURE:
            #         self._print_var_status(var, '', 0, EP, statement)
            # for item in returned_vars:
            #     var = returned_vars.get(item)
            #     if var.var_score == opcodes.VarScore.UNSECURE:
            #         self._print_var_status(var, '', 0, EP, statement)
            # for item in compiled_vars:
            #     var = compiled_vars.get(item)
            #     if var.var_score == opcodes.VarScore.UNSECURE:
            #         self._print_var_status(var, '', 0, EP, statement)

        return_status_log += ']'
        EP.analyze_result = return_status_log
        return return_status_log
