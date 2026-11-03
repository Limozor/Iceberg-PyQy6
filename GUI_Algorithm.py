import sys
import sqlite3
from datetime import datetime
from PyQt6 import uic
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog, QTableWidgetItem
from PyQt6.QtCore import Qt, QThread, pyqtSignal

from Master_Algorithm import Processing_Report
from Profile_GUI import ProfileWindow


class ScanThread(QThread):
    # Сигнал для передачи отчета обратно в главное окно, когда алгоритм закончит работу
    finished_signal = pyqtSignal(str, str, str)

    def __init__(self, file_path, general, suspicious, eof, exif, virustotal):
        super().__init__()
        self.file_path = file_path
        self.general = general
        self.suspicious = suspicious
        self.eof = eof
        self.exif = exif
        self.virustotal = virustotal

    def run(self):
        # Этот код работает в фоне и не вешает графический интерфейс
        result = Processing_Report(
            self.file_path,
            general=self.general,
            suspicious=self.suspicious,
            eof=self.eof,
            exif=self.exif,
            virustotal=self.virustotal
        )
        # Отправляем результаты в основное окно (статус, короткий отчет, полный отчет)
        self.finished_signal.emit(result[0], result[1], result[2])


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi("main.ui", self)

        self.current_file_path = None
        self.last_full_report = ""

        # Подключаем сигналы кнопок
        self.btn_select_file.clicked.connect(self.select_file)
        self.btn_start_scan.clicked.connect(self.start_scan)
        self.btn_save_txt.clicked.connect(self.save_txt_report)
        self.btn_open_profile.clicked.connect(self.open_profile_window)

        # Подготавливаем базу данных при старте
        self.init_database()
        self.load_history()

    def init_database(self):
        # 1. Создаем пустые таблицы с правильными именами, если их еще нет
        con = sqlite3.connect("iceberg_database.db")
        cur = con.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS History (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT,
                file_name TEXT,
                status TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS Profil (
                photo TEXT,
                name TEXT,
                second_name TEXT,
                gender TEXT,
                info TEXT
            )
        """)
        con.commit()
        con.close()

    def select_file(self):
        # 1. Открываем системное окно и выбираем картинку
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Выберите графический файл", "",
            "Графические файлы (*.png *.jpg *.jpeg *.bmp *.gif *.webp)"
        )

        if file_path:
            self.current_file_path = file_path
            display_name = file_path.split("/")[-1]
            self.label_file_path.setText(f"Выбран файл: {display_name}")
            # Очищаем прошлое сообщение об ошибке, если оно было
            self.textBrowser_report.clear()

    def start_scan(self):
        # 1. Если файл забыли выбрать, пишем ошибку прямо в окно отчета (без всплывающих окон)
        if not self.current_file_path:
            self.textBrowser_report.setText("Сначала выберите файл для проверки!")
            return

        # 2. Считываем, какие галочки нажал пользователь
        general = self.cb_general.isChecked()
        suspicious = self.cb_suspicious.isChecked()
        eof = self.cb_eof.isChecked()
        exif = self.cb_exif.isChecked()
        virustotal = self.cb_virustotal.isChecked()

        # 3. Пишем статус ожидания, выключаем кнопку старта и запускаем фоновый поток
        self.textBrowser_report.setText(
            "Идет проверка файла, пожалуйста подождите...\n(Окно не зависнет, ожидаем ответы от всех баз)")
        self.btn_start_scan.setEnabled(False)

        self.scan_thread = ScanThread(self.current_file_path, general, suspicious, eof, exif, virustotal)
        self.scan_thread.finished_signal.connect(self.process_scan_result)
        self.scan_thread.start()

    def process_scan_result(self, status_text, short_report, full_report):
        # 1. Включаем кнопку старта обратно, выводим результат на экран
        self.btn_start_scan.setEnabled(True)
        self.textBrowser_report.setText(short_report)
        self.last_full_report = full_report

        # 2. Если проверка реально состоялась (не ошибка выбора алгоритмов), сохраняем
        if status_text != "Ошибка":
            self.btn_save_txt.setEnabled(True)

            # Пишем в базу
            file_name = self.current_file_path.split("/")[-1]
            current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            con = sqlite3.connect("iceberg_database.db")
            cur = con.cursor()
            cur.execute(
                "INSERT INTO History (date, file_name, status) VALUES (?, ?, ?)",
                (current_date, file_name, status_text)
            )
            con.commit()
            con.close()

            # Обновляем таблицу истории в интерфейсе
            self.load_history()
        else:
            self.btn_save_txt.setEnabled(False)

    def load_history(self):
        # 1. Достаем всё из базы (самые новые сверху)
        con = sqlite3.connect("iceberg_database.db")
        cur = con.cursor()
        cur.execute("SELECT date, file_name, status FROM History ORDER BY id DESC")
        rows = cur.fetchall()
        con.close()

        # 2. Отрисовываем в таблице
        self.table_history.setRowCount(len(rows))
        for row_idx, row_data in enumerate(rows):
            for col_idx, col_data in enumerate(row_data):
                item = QTableWidgetItem(str(col_data))
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table_history.setItem(row_idx, col_idx, item)

        self.table_history.horizontalHeader().setStretchLastSection(True)

    def save_txt_report(self):
        if not self.last_full_report:
            return

        # 1. Открываем окно Windows для выбора папки сохранения
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить отчет", "report.txt", "Текстовые файлы (*.txt)"
        )

        # 2. Молча записываем файл без всплывающих окон об успехе
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.last_full_report)

    def open_profile_window(self):
        # 1. Передаем self, чтобы окно профиля могло вызывать self.load_history() при удалении
        self.profile_win = ProfileWindow(self)
        self.profile_win.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())