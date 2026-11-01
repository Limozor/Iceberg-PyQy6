#Каз,нел пом
from ping3 import ping
from EXIF import Check_EXIF
from VirusTotal import Virus_Total_Scan
from Algorithms import Check_General, Check_EOF, Cheak_Suspicious


def Processing_Report(
    file_path,
    general=False,
    suspicious=False,
    eof=False,
    exif=False,
    virustotal=False
):
    if not any([general, suspicious, eof, exif, virustotal]):
        msg = "Не был выбран не один алгоритм проверки"
        return ["Ошибка", msg, msg]

    # Запуск только выбранных алгоритмов
    Check_General_res = Check_General(file_path) if general else [False, False]
    Cheak_Suspicious_res = Cheak_Suspicious(file_path) if suspicious else [False, False]
    Check_EOF_res = Check_EOF(file_path) if eof else [False, False]
    Check_EXIF_res = Check_EXIF(file_path) if exif else [False, False]

    List_Checks = [Check_General_res, Cheak_Suspicious_res, Check_EOF_res, Check_EXIF_res]

    Report_UNSAFE = []
    Report_ODD = []

    # Отдельный список для детального отчета VirusTotal
    vt_full_details = []

    # Сбор данных от локальных алгоритмов
    for lst in List_Checks:
        first_unit, second_unit = lst[0], lst[1]
        if first_unit:
            Report_UNSAFE.extend(lst[2:])
        elif second_unit:
            Report_ODD.extend(lst[2:])

    # 2. Обработка VirusTotal если чекбокс
    if virustotal:
        dostup = isinstance(ping("virustotal.com"), float)
        if dostup:
            VirusTotal_Universal_res = Virus_Total_Scan(file_path)

            if VirusTotal_Universal_res[0] == False:
                vt_stats = VirusTotal_Universal_res[3]
                vt_results = VirusTotal_Universal_res[4]

                malicious_cnt = vt_stats.get("malicious", 0)
                suspicious_cnt = vt_stats.get("suspicious", 0)
                harmless_cnt = vt_stats.get("harmless", 0)
                undetected_cnt = vt_stats.get("undetected", 0)

                # Строка для окна программы  при наличии угроз
                vt_short_msg = (
                    f"VirusTotal обнаружил угрозы! "
                    f"Вредоносных движков: {malicious_cnt}, Подозрительных: {suspicious_cnt}."
                )

                if VirusTotal_Universal_res[1] == True:
                    Report_UNSAFE.append(vt_short_msg)
                elif VirusTotal_Universal_res[2] == True:
                    Report_ODD.append(vt_short_msg)

                # Полный отчет VirusTotal для файла
                vt_full_details.append("=== ПОЛНЫЙ ОТЧЕТ VIRUSTOTAL ===")
                vt_full_details.append(
                    f"Статистика: Вредоносных: {malicious_cnt} | "
                    f"Подозрительных: {suspicious_cnt} | "
                    f"Безопасных: {harmless_cnt} | "
                    f"Не обнаружено: {undetected_cnt}"
                )
                vt_full_details.append("Результаты по антивирусным движкам:")

                for engine_name, engine_data in vt_results.items():
                    category = engine_data.get("category", "unknown")
                    result_name = engine_data.get("result") or "чисто"
                    vt_full_details.append(f" - {engine_name}: {category} ({result_name})")

    # Копирование результатов проверок для полного отчета без VT
    local_alg = []
    for lst in List_Checks:
        if lst[0] or lst[1]:
            local_alg.extend(lst[2:])

    report_flag = False
    status_report_text = ""

    # Вариант 1: Файл полностью безопасен
    if (not Report_UNSAFE) and (not Report_ODD):
        report_flag = True
        status_report_text = "Безопасный"
        clean_text = """🧊 Сканирование завершено. Файл чист.
Проверка проведена по всем актуальным базам и алгоритмам Айсберга. Вредоносная активность не выявлена. Доступ к содержимому безопасен. 💙"""
        report = clean_text

        # Если VirusTotal был включен добавляем в полный отчет
        if vt_full_details:
            report_file = clean_text + "\n\n" + "\n".join(vt_full_details)
        else:
            report_file = clean_text

    # Вариант 2: Опасные угрозы
    elif Report_UNSAFE and report_flag == False:
        report_flag = True
        status_report_text = "Вредоносный"
        short_combined = "\n".join(Report_UNSAFE + Report_ODD)
        report = f"""ВНИМАНИЕ
‼ ФАЙЛ ОПАСЕН ‼
{short_combined}
"""
        # В полный отчет входят все проверки
        report_file = "\n".join(local_alg + vt_full_details)

    # Вариант 3: Подозрительные совпадения
    elif Report_ODD and report_flag == False:
        report_flag = True
        status_report_text = "Подозрительный"
        short_odd = "\n".join(Report_ODD)
        report = f"""ВНИМАНИЕ 
⚠ ФАЙЛ ПОДОЗРИТЕЛЬНЫЙ ⚠
{short_odd}
"""
        # В полный отчет входят все проверки
        report_file = "\n".join(local_alg + vt_full_details)

    return [status_report_text, report, report_file]