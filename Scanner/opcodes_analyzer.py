import re
import copy
import opcodes
import opcodes_parser as op

predefined_variables = ['_GET', '_POST', '_COOKIE', '_REQUEST']


def score_spread(score, var, cmp, tmp, ret):
    for c in cmp:
        if var.ID in c.value and c.var_score != opcodes.VarScore.SECURE:
            c.var_score = score
    for t in tmp:
        if var.ID in t.value and t.var_score != opcodes.VarScore.SECURE:
            t.var_score = score
    for r in ret:
        if var.ID in r.value and r.var_score != opcodes.VarScore.SECURE:
            r.var_score = score


def analyze(EP, V):
    Statements = op.get_statements_from_opcodes(EP.opcodes)
    compiled_vars = copy.deepcopy(EP.compiled_variables)
    temporary_vars = []
    returned_vars = []
    fcall_flag = 0
    fcall_count = 0
    fcall_buffer = []
    for s in Statements:
        # ОТЛАДОЧНЫЙ ВЫВОД  
        # Вывод compiled_vars для предыдущего statement
        print("\nCOMPILED VARS:\n")
        for cv in compiled_vars:
            print(cv.ID, cv.name, cv.var_type.name, cv.value, cv.var_score.name, "\n")
        # Вывод temporary_vars для предыдущего statement
        print("\nTEMPORARY VARS:\n")
        for tv in temporary_vars:
            print(tv.ID, tv.name, tv.var_type.name, tv.value, tv.var_score.name, "\n")
        # Вывод returned_vars для предыдущего statement
        print("\nRETURNED VARS:\n")
        for rv in returned_vars:
            print(rv.ID, rv.name, rv.var_type.name, rv.value, rv.var_score.name, "\n")

        print(". . .\n")

        # ОЧИСТКА temporary_vars для каждого statement
        temporary_vars.clear()

        # АНАЛИЗ ОПКОДОВ
        for o in s.opcodes:
            # Если видим операцию ASSIGN, то в compiled_vars ищем переменную из первого операнда
            # и записываем в нее переменную из второго операнда. Возможные варианты:
            # ASSIGN !1, ~2
            # ASSIGN !1, $2
            # ASSIGN !1, !2
            if o.operation == "ASSIGN" and re.match(r"!\d", o.operands[0]):
                for cv in compiled_vars:
                    if cv.ID == o.operands[0]:
                        cv.value = o.operands[1]

                        # Если видим операцию CONCAT, для временных переменных: либо записываем операнды в существующую переменную,
            # либо добавляем новую переменную, для скомпилированных: записываем операнды в существующую переменную.
            # CONCAT     ~1      ~2, ~3 (любые комбинации пар переменных ~, $, ! и строк "")
            # CONCAT     !1      ~2, ~3 (любые комбинации пар переменных ~, $, ! и строк "")
            if "CONCAT" in o.operation:  # CONCAT, FAST_CONCAT
                if re.match(r"~\d", o.ret_value):
                    flag = 0
                    for tv in temporary_vars:
                        if tv.ID == o.ret_value:
                            tv.value = o.operands
                            flag = 1
                    if flag == 0:
                        var = opcodes.Variable()
                        var.ID = o.ret_value
                        var.var_type = opcodes.VarType.TEMPORARY
                        var.value = o.operands
                        temporary_vars.append(var)
                if re.match(r"!\d", o.ret_value):
                    for cv in compiled_vars:
                        if cv.ID == o.ret_value:
                            cv.value = o.operands

            # Если видим операцию FETCH_R, и она применяется к predefined_variables, либо записываем операнд
            # в существующую переменную, либо добавляем новую переменную и помечаем переменную небезопасной.
            # FETCH_R    ~1      '_REQUEST'
            # FETCH_R    ~1      '_GET'
            # FETCH_R    ~1      '_POST'
            # FETCH_R    ~1      '_COOKIE'
            if o.operation == "FETCH_R" and o.operands[0] in predefined_variables:
                flag = 0
                for tv in temporary_vars:
                    if tv.ID == o.ret_value:
                        tv.value = o.operands
                        tv.var_score = opcodes.VarScore.UNSECURE
                        flag = 1
                if flag == 0:
                    var = opcodes.Variable()
                    var.ID = o.ret_value
                    var.var_type = opcodes.VarType.TEMPORARY
                    var.value = o.operands
                    var.var_score = opcodes.VarScore.UNSECURE
                    temporary_vars.append(var)

            # Если видим операцию FETCH_DIM_R
            # Все варианты:
            # FETCH_DIM_R    ~1      ~2, ~3 (любые комбинации пар переменных ~, $, ! и строк "")
            # FETCH_DIM_R    !1      ~2, ~3 (любые комбинации пар переменных ~, $, ! и строк "")
            # FETCH_DIM_R    $1      ~2, ~3 (любые комбинации пар переменных ~, $, ! и строк "")
            if o.operation == "FETCH_DIM_R" and "~" in o.ret_value:
                if re.match(r"~\d", o.ret_value):
                    flag = 0
                    for tv in temporary_vars:
                        if tv.ID == o.ret_value:
                            tv.value = o.operands
                            flag = 1
                    if flag == 0:
                        var = opcodes.Variable()
                        var.ID = o.ret_value
                        var.var_type = opcodes.VarType.TEMPORARY
                        var.value = o.operands
                        temporary_vars.append(var)
                if re.match(r"!\d", o.ret_value):
                    for cv in compiled_vars:
                        if cv.ID == o.ret_value:
                            cv.value = o.operands
                if re.match(r"$\d", o.ret_value):
                    flag = 0
                    for rv in returned_vars:
                        if rv.ID == o.ret_value:
                            rv.value = o.operands
                            flag = 1
                    if flag == 0:
                        var = opcodes.Variable()
                        var.ID = o.ret_value
                        var.var_type = opcodes.VarType.RETURNED
                        var.value = o.operands
                        returned_vars.append(var)

            # Если видим операцию ECHO, то помечаем назащищенные переменные как опасные и выводим предупреждение
            # Все варианты:
            # ECHO    ~1
            # ECHO    !1
            # ECHO    $1
            # ECHO    "string"
            if o.operation in V.dangerous_functions:  # На данный момент таких кодов операций только один: ECHO
                for tv in temporary_vars:
                    if tv.ID in o.operands and tv.var_score != opcodes.VarScore.SECURE:
                        tv.var_score = opcodes.VarScore.DANGEROUS
                for cv in compiled_vars:
                    if cv.ID in o.operands and cv.var_score != opcodes.VarScore.SECURE:
                        cv.var_score = opcodes.VarScore.DANGEROUS
                for rv in returned_vars:
                    if rv.ID in o.operands and rv.var_score != opcodes.VarScore.SECURE:
                        rv.var_score = opcodes.VarScore.DANGEROUS


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

            # Поэтому надо вести счетчик fcall_count, чтобы потом снять флаг fcall_flag только при нужном DO_FCALL
            if "INIT_" in o.operation and "CALL" in o.operation:  # INIT_FCALL, INIT_FCALL_BY_NAME, INIT_METHOD_CALL
                fcall_count += 1
                # если мы во вложенном fcall, и уже стоит флаг fcall_flag = 2
                # и встретилась защитная, то мы ставим 1 (защитная функция вложена в опасную)
                # запомниаем имя функции в буфер
                if o.operands[0] in V.protective_functions:
                    fcall_flag = 1
                    fcall_buffer.append([])
                    fcall_buffer[fcall_count - 1].append(o.operands[0])
                # если мы во вложенном fcall, и уже стоит флаг fcall_flag = 1 и
                # встретилась опасная, то мы НЕ ставим 2 (опасная функция вложена в защитную)
                # запомниаем имя функции в буфер
                if o.operands[0] in V.dangerous_functions and fcall_flag != 1:
                    fcall_flag = 2
                    fcall_buffer.append([])
                    fcall_buffer[fcall_count - 1].append(o.operands[0])

            if o.operation == "DO_FCALL":
                fcall_count -= 1
                # Для лога надо запомнить название вызываемой функции,
                # поэтому запишем ее в операнды (там свободно)
                if fcall_count >= 0 and len(fcall_buffer) > 0:
                    o.operands.append(fcall_buffer[fcall_count][0])
                if fcall_count == 0:  # если это самый внешний fcall,
                    # то снимаем флаг fcall_flag
                    fcall_flag = 0
                    # print(fcall_buffer)
                    if re.match(r"$\d", o.ret_value):
                        # и фиксируем возвращаемую переменную $ 
                        # (накопленные в буфер значения операндов INIT_FCALL, SEND_VAL, SEND_VAR)
                        var = opcodes.Variable()
                        var.ID = o.ret_value
                        var.var_type = opcodes.VarType.RETURNED
                        var.value = fcall_buffer
                        returned_vars.append(var)
                        fcall_buffer.clear()

            # SEND_VAR   !1
            # SEND_VAR   $1
            if "SEND_VAR" in o.operation:
                if fcall_flag == 1:
                    if re.match(r"!\d", o.operands[0]):
                        fcall_buffer[fcall_count - 1].append(o.operands[0])
                        for cv in compiled_vars:
                            if cv.ID == o.operands[0]:
                                cv.var_score = opcodes.VarScore.SECURE
                    if re.match(r"$\d", o.operands[0]):
                        fcall_buffer[fcall_count - 1].append(o.operands[0])
                        for rv in returned_vars:
                            if rv.ID == o.operands[0]:
                                rv.var_score = opcodes.VarScore.SECURE
                if fcall_flag == 2:
                    fcall_buffer[fcall_count - 1].append(o.operands[0])
                    if re.match(r"!\d", o.operands[0]):
                        for cv in compiled_vars:
                            if cv.ID == o.operands[0] and cv.var_score != opcodes.VarScore.SECURE:
                                cv.var_score = opcodes.VarScore.DANGEROUS
                    fcall_buffer[fcall_count - 1].append(o.operands[0])
                    if re.match(r"$\d", o.operands[0]):
                        for rv in returned_vars:
                            if rv.ID == o.operands[0] and rv.var_score != opcodes.VarScore.SECURE:
                                rv.var_score = opcodes.VarScore.DANGEROUS
                                # SEND_VAL   ~1

            # SEND_VAL   'string'
            # SEND_VAL   int
            if "SEND_VAL" in o.operation:
                if fcall_flag == 1:
                    fcall_buffer[fcall_count - 1].append(o.operands[0])
                    if re.match(r"~\d", o.operands[0]):
                        for tv in temporary_vars:
                            if tv.ID == o.operands[0]:
                                tv.var_score = opcodes.VarScore.SECURE
                if fcall_flag == 2:
                    fcall_buffer[fcall_count - 1].append(o.operands[0])
                    if re.match(r"~\d", o.operands[0]):
                        for tv in temporary_vars:
                            if tv.ID == o.operands[0] and tv.var_score != opcodes.VarScore.SECURE:
                                tv.var_score = opcodes.VarScore.DANGEROUS

                                # КОНЕЦ АНАЛИЗА ОПКОДОВ

        # Распространение небезопасных и опасных меток по переменным
        # Вывод сообщений о небезопасных и опасных переменных
        for tv in temporary_vars:
            score_spread(opcodes.VarScore.UNSECURE, tv, compiled_vars, temporary_vars, returned_vars)
            score_spread(opcodes.VarScore.DANGEROUS, tv, compiled_vars, temporary_vars, returned_vars)
            if tv.var_score == opcodes.VarScore.UNSECURE:
                print("\nUNSECURE: Temporary variable", tv.ID, " used without a protective function \nin file:",
                      EP.filename.strip(), "\nin function:", EP.function_name)
            if tv.var_score == opcodes.VarScore.DANGEROUS:
                function = o.operation
                if (function == "DO_FCALL") and (len(o.operands) > 0):
                    function = o.operands[0]
                if function in V.dangerous_functions:
                    print("\nDANGEROUS: Temporary variable", tv.ID, " used in a dangerous function", function,
                          "without a protective function \nin file:", EP.filename.strip(), "\nin function:",
                          EP.function_name)
                else:
                    print("\nDANGEROUS: Temporary variable", tv.ID,
                          " used in a dangerous function without a protective function \nin file:", EP.filename.strip(),
                          "\nin function:", EP.function_name)
        for cv in compiled_vars:
            score_spread(opcodes.VarScore.UNSECURE, cv, compiled_vars, temporary_vars, returned_vars)
            score_spread(opcodes.VarScore.DANGEROUS, cv, compiled_vars, temporary_vars, returned_vars)
            if cv.var_score == opcodes.VarScore.UNSECURE:
                print("\nUNSECURE: Compiled variable", cv.ID, "=", cv.name,
                      " used without a protective function \nin file:", EP.filename.strip(), "\nin function:",
                      EP.function_name)
            if cv.var_score == opcodes.VarScore.DANGEROUS:
                function = o.operation
                if function == "DO_FCALL":
                    function = o.operands[0]
                if function in V.dangerous_functions:
                    print("\nDANGEROUS: Compiled variable", cv.ID, "=", cv.name, "used in a dangerous function",
                          function, "without a protective function \nin file:", EP.filename.strip(), "\nin function:",
                          EP.function_name)
                else:
                    print("\nDANGEROUS: Compiled variable", cv.ID, "=", cv.name,
                          "used in a dangerous function without a protective function \nin file:", EP.filename.strip(),
                          "\nin function:", EP.function_name)
        for rv in returned_vars:
            score_spread(opcodes.VarScore.UNSECURE, rv, compiled_vars, temporary_vars, returned_vars)
            score_spread(opcodes.VarScore.DANGEROUS, rv, compiled_vars, temporary_vars, returned_vars)
            if rv.var_score == opcodes.VarScore.UNSECURE:
                print("\nUNSECURE: Compiled variable", rv.ID, " used without a protective function \nin file:",
                      EP.filename.strip(), "\nin function:", EP.function_name)
            if rv.var_score == opcodes.VarScore.DANGEROUS:
                function = o.operation
                if function == "DO_FCALL":
                    function = o.operands[0]
                if function in V.dangerous_functions:
                    print("\nDANGEROUS: Returned variable", rv.ID, "used in a dangerous function", function,
                          "without a protective function \nin file:", EP.filename.strip(), "\nin function:",
                          EP.function_name)
