import sqlite3
from PyQt6 import uic
from PyQt6.QtWidgets import QMainWindow, QFileDialog
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import Qt
from requests import delete


class ProfileWindow(QMainWindow):
    def __init__(self, main_window):
        super().__init__()
        uic.loadUi("profil.ui", self)

        self.main_window = main_window
        self.current_photo_path = ""

        # Подключаем кранки к кнопкам
        self.btn_change_avatar.clicked.connect(self.load_avatar)
        self.btn_save_settings.clicked.connect(self.save_profile)
        self.btn_delete_data.clicked.connect(self.delete_all_data)

        # Подгружаем данные из базы сразу при открытии окна
        self.profile_db()

    def keyPressEvent(self, event):
        # зажаты одновременно Alt и Shift
        if event.modifiers() == (Qt.KeyboardModifier.AltModifier
                                 | Qt.KeyboardModifier.ShiftModifier):
            # нажата D
            if event.key() == Qt.Key.Key_D:
                self.delete_all_data()
                self.close()

    def profile_db(self):
        # 1. Забираем единственную запись из таблицы
        con = sqlite3.connect("iceberg_database.db")
        cur = con.cursor()
        cur.execute("SELECT photo, name, second_name, gender, info FROM Profil")
        row = cur.fetchone()
        con.close()

        # 2. Если профиль уже был сохранен ранее, раскидываем данные по полям
        if row:
            photo_path, name, second_name, gender, info = row

            if name: self.lineEdit_name.setText(name)
            if second_name: self.lineEdit_second_name.setText(second_name)
            if info: self.textEdit_desc_2.setText(info)

            if gender:
                index = self.comboBox_gender.findText(gender)
                if index >= 0:
                    self.comboBox_gender.setCurrentIndex(index)

            # 3. Загружаем и красиво обрезаем фотку по пути из базы
            if photo_path:
                self.current_photo_path = photo_path
                pixmap = QPixmap(photo_path)
                if not pixmap.isNull():
                    size = min(pixmap.width(), pixmap.height())
                    x = (pixmap.width() - size) // 2
                    y = (pixmap.height() - size) // 2
                    cropped = pixmap.copy(x, y, size, size)
                    scaled = cropped.scaled(100, 100, Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                                            Qt.TransformationMode.SmoothTransformation)

                    self.label_avatar.setPixmap(scaled)
                    self.label_avatar.setText("")

    def load_avatar(self):
        # 1. Выбираем картинку на компьютере
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Выберите фото профиля", "", "Изображения (*.png *.jpg *.jpeg *.bmp)"
        )

        # 2. Если выбрали, просто сохраняем путь и выводим на экран
        if file_path:
            self.current_photo_path = file_path

            pixmap = QPixmap(file_path)
            size = min(pixmap.width(), pixmap.height())
            x = (pixmap.width() - size) // 2
            y = (pixmap.height() - size) // 2
            cropped = pixmap.copy(x, y, size, size)
            scaled = cropped.scaled(100, 100, Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                                    Qt.TransformationMode.SmoothTransformation)

            self.label_avatar.setPixmap(scaled)
            self.label_avatar.setText("")

    def save_profile(self):
        # 1. Собираем тексты из всех полей
        name = self.lineEdit_name.text().strip()
        second_name = self.lineEdit_second_name.text().strip()
        gender = self.comboBox_gender.currentText()
        info = self.textEdit_desc_2.toPlainText().strip()

        # 2. Записываем в базу (старую строку сносим, чтобы профиль всегда был один)
        con = sqlite3.connect("iceberg_database.db")
        cur = con.cursor()
        cur.execute("DELETE FROM Profil")
        cur.execute(
            "INSERT INTO Profil (photo, name, second_name, gender, info) VALUES (?, ?, ?, ?, ?)",
            (self.current_photo_path, name, second_name, gender, info)
        )
        con.commit()
        con.close()

        # 3. Просто тихо закрываем окно профиля
        self.close()

    def delete_all_data(self):
        # 1. Моментально стираем всё из базы без лишних вопросов
        con = sqlite3.connect("iceberg_database.db")
        cur = con.cursor()
        cur.execute("DELETE FROM History")
        cur.execute("DELETE FROM Profil")
        con.commit()
        con.close()

        # 2. Очищаем все поля на экране
        self.lineEdit_name.clear()
        self.lineEdit_second_name.clear()
        self.textEdit_desc_2.clear()
        self.comboBox_gender.setCurrentIndex(0)
        self.label_avatar.clear()
        self.label_avatar.setText("ФОТО")
        self.current_photo_path = ""

        # 3. Даем команду главному окну обновить таблицу истории (она станет пустой)
        self.main_window.load_history()