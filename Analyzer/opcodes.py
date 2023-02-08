from parse import *
from enum import Enum


class VarType(Enum):
    UNDEFINED = 0
    COMPILED = 1  # !
    TEMPORARY = 2  # ~
    RETURNED = 3  # $


class VarScore(Enum):
    UNDEFINED = 0
    SECURE = 1  # хранит польз. данные, к которым применена защитная функция
    UNSECURE = 2  # хранит польз. данные, к которым не применена защитная функция, но и в опасных ф-ях не использовалась
    DANGEROUS = 3  # хранит польз. данные, к которым не применена защитная функция, и использовалась в опасных ф-ях


class Variable:
    def __init__(self):
        self.ID = 0
        self.name = ""
        self.var_type = VarType.UNDEFINED
        self.value = []
        self.var_score = VarScore.UNDEFINED


class Opcode:
    def __init__(self):
        self.index = 0
        self.operation = ""
        self.ret_value = ""
        self.operands = []


class EntryPoint:
    def __init__(self):
        self.filename = ""
        self.function_name = ""
        self.number_of_ops = 0
        self.compiled_variables = []
        self.opcodes = []
        self.analyze_result = ""

    def set_compiled_vars(self, vars_str):
        for vs in vars_str.split(','):
            cv = parse("!{var_id} = ${var_name}", vs.strip())
            if cv is not None:
                id_ = '!' + cv['var_id']
                name_ = '$' + cv['var_name']
                var = Variable()
                var.ID = id_
                var.name = name_
                var.var_type = VarType.COMPILED
                self.compiled_variables.append(var)


class Statement:
    def __init__(self):
        self.index = 0
        self.opcode_number = 0
        self.opcodes = []


class VulnSignature:
    def __init__(self):
        self.ID = 0
        self.name = ""
        self.danger_level = VarScore.UNDEFINED
        self.opcodes_number = 0
        self.signature = []
        self.def_functions = []
