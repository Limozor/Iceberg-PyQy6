import os
from pathlib import Path
from hachoir.parser import createParser


def Check_General(path):
    report = [False, False]

    # Проверяем размер
    if os.path.getsize(path) == 0:
        report[1] = True
        report.append("Файл пустой попробуйте отправить этот файл снова или отправьте другой")

    # Проверяем формат
    parser = createParser(path)

    if parser is None:
        report[1] = True
        report.append("Формат файла не определён, проверьте файл и попробуйте снова")

    # Проверяем структуру файла
    try:
        for _ in parser:
            pass

    except Exception:
        report[0] = True
        report.append("Файл повреждён")

    return report


def Cheak_Suspicious(master_file):
    report = [False, False]
    safe_suffixes = {'.png', '.jpg', '.jpeg', ".webp", ".gif", ".heic", ".mp3", ".mp4", ".mp5"}
    path = Path(master_file)
    suffixes = path.suffixes
    if len(suffixes) >= 2:
        report[0] = True
        report.append("Количество расширений не допустимо (двойные расширения)")
    last_suffix = path.suffix.lower()
    if last_suffix not in safe_suffixes:
        report[0] = True
        report.append("Расширение не безопасно")
    return report


def Check_EOF(master_file):
    report = [False, False]
    signatures = [b'\xff\xd9', b'\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82']
    with open(master_file, 'rb') as f:
        content = f.read()
        for sig in signatures:
            if content.endswith(sig):
                return report
    report[0] = True
    report.append("В файле обнаружен вредоносный код: подозрительный конец файла")
    return report
