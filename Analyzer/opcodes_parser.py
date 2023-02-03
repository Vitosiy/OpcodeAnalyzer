import re
from parse import *
from opcodes import *

opcode_line_pattern = re.compile(r"[\d]{1,10}\*{0,1} * [\d]{0,10} * E{0,1} >{0,1} >{0,1} * ([A-Z]{1,32}_{0,1}){0,10} *")
filename_pattern = re.compile(r"^filename:\s*(.*?\.php)")
funcname_pattern = re.compile(r"^function name:\s*(.*?)\n")
ops_number_pattern = re.compile(r"^number of ops:\s*(.*?)\n")
compiled_vars_pattern = re.compile(r"^compiled vars:\s*(.*?)\n")


def parse_opcode_line(opcode_line):
    line = opcode_line.split('  ')
    #dbg_line = line
    line = [x.replace('*', '').replace('>', '').replace('\n', '').strip() for x in line]
    line = [x for x in line if x != 'E' and x != 'global' and x != '+=']
    line_items = []

    for l in line:
        if l != '':
            line_items.append(l)

    line = [x.replace('\'', '') for x in line]

    if len(line_items) < 2:
        print("parse_opcode_line: Error, unexpected number of items in a line.")
        print("line:", opcode_line)
    else:  # if len(line_items) >= 2
        if line_items[1].isdigit():  # оставляем лишь линейные индексы (ветки и циклы игнорируем)
            line_items.pop(0)

    if len(line_items) > 2 and line_items[2].isdigit() and len(line_items) != 3:
        line_items.pop(2)  # избавляемся от значений из колонки ext

    if len(line_items) not in [2, 3,
                               4]:  # должны остаться значения из колонок индекс, опкод, возвращаемое значение и операнды
        print("parse_opcode_line: Error, unexpected number of items in a line.")
        print("line:", opcode_line)

    opcode = Opcode()
    opcode.index = line_items[0]

    line_items = [x.replace('\'', '') for x in line_items]

    if len(line_items) < 2:
        return opcode

    opcode.operation = line_items[1]
    if len(line_items) == 3:  # определяем какой колонке принадлежит 3-й элемент - возвращаемое значение или операнд
        if line_items[2] == line[-1]:
            opcode.operands = line_items[2].split(', ')
        else:
            opcode.ret_value = line_items[2]
    elif len(line_items) == 4:
        opcode.ret_value = line_items[2]
        opcode.operands = line_items[3].split(', ')

    return opcode


def parse_file(filename):
    EntryPoints = {}

    file = open(filename, "r")
    ep_count = 0
    while True:
        line = file.readline()
        if not line:
            break
        if "Finding entry points" in line:
            ep_count += 1
            EP = EntryPoint()
            done = 0
            while True:
                line = file.readline()
                if not line:
                    break
                if done == 1:
                    break

                tmp_regex_object = re.search(filename_pattern, line)
                if tmp_regex_object:
                    # filename:       qwerty
                    filename = line[tmp_regex_object.regs[1][0]:tmp_regex_object.regs[1][1]]
                    if filename:
                        EP.filename = filename
                        if not EntryPoints.get(EP.filename):
                            EntryPoints[EP.filename] = {}
                    # function name:  ytrewq
                    line = file.readline()

                    if not line:
                        break

                    tmp_regex_object = re.search(funcname_pattern, line)
                    func = line[tmp_regex_object.regs[1][0]:tmp_regex_object.regs[1][1]]

                    if EntryPoints.get(EP.filename).get(func):
                        done = 1
                        break

                    if func:
                        EP.function_name = func

                    # number of ops:  12345
                    line = file.readline()
                    if not line:
                        break

                    tmp_regex_object = re.search(ops_number_pattern, line)

                    if tmp_regex_object is None:
                        print('parse_file: Undocumented function call!')
                        print('Function name: ', func)
                        done = 1
                        break

                    ops_num = line[tmp_regex_object.regs[1][0]:tmp_regex_object.regs[1][1]]

                    if ops_num is None:
                        print('ops_num is None')
                        break

                    # if not re.match(r"^[-+]?[0-9]+\\n$", ops_num['value'], re.M):
                    #   break

                    EP.number_of_ops = ops_num

                    # compiled vars:  !0 = $qwer123, !1 = $321rewq, !2 = $asdfg
                    line = file.readline()
                    if not line:
                        break

                    tmp_regex_object = re.search(compiled_vars_pattern, line)
                    vars_str = line[tmp_regex_object.regs[1][0]:tmp_regex_object.regs[1][1]]
                    if vars_str:
                        EP.set_compiled_vars(vars_str)

                    # line #* E I O op fetch ext return operands
                    line = file.readline()
                    if not line:
                        break

                    # -------------------------------------------
                    line = file.readline()
                    if not line:
                        break

                    for i in range(0, int(ops_num)):
                        # 123 321 E > QWER_TY
                        line = file.readline()
                        if re.search(opcode_line_pattern, line):
                            op = parse_opcode_line(line)
                            EP.opcodes.append(op)
                        else:
                            if not re.match(r'^\s*$', line):
                                print("parse_file: Error, unexpected line.")
                                print("line:", line)
                                break

                    EntryPoints[EP.filename][EP.function_name] = EP
                    done = 1

    file.close()

    return EntryPoints


# Если не дождаться завершения всех вызовов функций, в опкоды может быть записана обрывающаяся точка входа (строк опкодов меньше, чем заявлено), кроме того следующая точка входа начинается без переноса строки, что приводит к ошибкам парсинга.
# Данная функция добавляет переносы строки для всех вхождений "Finding entry points" и записывает все в новый файл.
def parse_error_correction(old_file):
    # old_file = open(filename, "r")
    new_filename = "../Logs/opcodes.txt"
    new_file = open(new_filename, "a")
    new_file.truncate(0)
    while True:
        line = old_file.readline()
        if not line:
            break
        if "Finding entry points" in line:
            correct_part = line.replace("Finding entry points", "")
            if correct_part:
                new_file.write(correct_part)
                new_file.write("\nFinding entry points\n")
        else:
            new_file.write(line)
            # old_file.close
    new_file.close()


# Печать в лог информации о всех точках входа в исследуемом файле.
# На вход подается массив точек входа после исполнения функции parse_file.
def print_entry_points(EntryPoints):
    ep_filename = "../Logs/entry_points.txt"
    ep_file = open(ep_filename, "a")
    ep_file.truncate(0)
    for item_file in EntryPoints:
        file_eps = EntryPoints.get(item_file)
        ep_file.write("-----------------------------------------------\n")
        ep_file.write("Filename: {}\n".format(item_file))
        ep_index = 1
        for item in file_eps:
            eps = file_eps.get(item)
            ep_file.write("-----------------------------------------------\n")
            ep_file.write("Entry point №{}\n".format(ep_index))
            ep_file.write("Function name: {}\n".format(eps.function_name))
            ep_file.write("Number of opcodes: {}\n".format(eps.number_of_ops))
            ep_file.write("Compiled variables:\n")
            ep_file.write("---------------------\n")
            for cv in eps.compiled_variables:
                ep_file.write("{}\t{}\n".format(cv.ID, cv.name))
            ep_file.write("---------------------\n")
            ep_file.write("Opcodes:\n")
            ep_file.write("---------------------\n")
            for o in eps.opcodes:
                ep_file.write("{}\t{} \t{}\t{}\n".format(o.index, o.operation, o.ret_value, ', '.join(o.operands)))
            ep_file.write("---------------------\n")
            ep_index += 1
    ep_file.close()


def get_statements_from_opcodes(opcodes):
    Statements = []
    index = 1
    STMT = Statement()
    for o in opcodes:
        if o.operation == "EXT_STMT":
            Statements.append(STMT)
            STMT = Statement()
            STMT.index = index
            STMT.opcode_number = o.index
            index += 1
        STMT.opcodes.append(o)
    Statements.append(STMT)
    Statements.pop(0)
    return Statements


def print_statements(Statements):
    stmt_filename = "../Logs/statements.txt"
    stmt_file = open(stmt_filename, "a")
    stmt_file.truncate(0)
    for s in Statements:
        stmt_file.write("Statement №{} \n".format(s.index))
        for o in s.opcodes:
            stmt_file.write("{}\t{} \t{}\t{}\n".format(o.index, o.operation, o.ret_value, ', '.join(o.operands)))
        stmt_file.write("----------------------------------------------------\n")
    stmt_file.close()
