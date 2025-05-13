import base64
import hashlib
import codecs
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import scrolledtext
import threading

# Цветовая схема для различных частей интерфейса
COLORS = {
    'header': '#DAA520',       # Золотистый цвет для заголовков
    'label': '#1E90FF',        # Синий для названий алгоритмов
    'result': '#949494',       # Светло-серый для результатов кодирования
    'input_label': '#228B22',  # Зеленый для метки ввода
    'warning': '#FF4500'       # Оранжево-красный для предупреждений
}

# region Создание русского алфавита с буквой Ё
def make_russian_alphabet():
    """
    Создает списки русских заглавных и строчных букв, включая букву Ё/ё,
    так как она не входит в непрерывный диапазон Unicode.
    """
    rus_upper = [chr(c) for c in range(ord('А'), ord('Е')+1)]  # А-Е
    rus_upper += ['Ё']  # Добавляем Ё
    rus_upper += [chr(c) for c in range(ord('Ж'), ord('Я')+1)]  # Ж-Я
    rus_lower = [c.lower() for c in rus_upper]  # Строчные буквы
    return rus_upper, rus_lower

# Глобальные переменные с алфавитами для шифров
RUS_UPPER, RUS_LOWER = make_russian_alphabet()
ENG_UPPER = [chr(c) for c in range(ord('A'), ord('Z')+1)]
ENG_LOWER = [chr(c) for c in range(ord('a'), ord('z')+1)]
# endregion

# region Функция Цезаря с поддержкой русского и английского алфавитов
def caesar_cipher(text, shift=3):
    """
    Применяет шифр Цезаря с заданным сдвигом ко всем буквам текста.
    Поддерживает английский и русский алфавиты, включая букву Ё.
    Небуквенные символы остаются без изменений.
    """
    result = []
    for char in text:
        if char in ENG_UPPER:
            idx = ENG_UPPER.index(char)
            result.append(ENG_UPPER[(idx + shift) % 26])
        elif char in ENG_LOWER:
            idx = ENG_LOWER.index(char)
            result.append(ENG_LOWER[(idx + shift) % 26])
        elif char in RUS_UPPER:
            idx = RUS_UPPER.index(char)
            result.append(RUS_UPPER[(idx + shift) % 33])
        elif char in RUS_LOWER:
            idx = RUS_LOWER.index(char)
            result.append(RUS_LOWER[(idx + shift) % 33])
        else:
            # Все остальные символы (пробелы, цифры, знаки) не меняются
            result.append(char)
    return ''.join(result)
# endregion

# region Функция Атбаш с поддержкой русского и английского алфавитов
def atbash_cipher(text):
    """
    Реализует шифр Атбаш - замену буквы на "зеркальную" в алфавите.
    Работает с английским и русским алфавитами (включая Ё).
    Небуквенные символы остаются без изменений.
    """
    result = []
    for char in text:
        if char in ENG_UPPER:
            result.append(ENG_UPPER[25 - ENG_UPPER.index(char)])
        elif char in ENG_LOWER:
            result.append(ENG_LOWER[25 - ENG_LOWER.index(char)])
        elif char in RUS_UPPER:
            result.append(RUS_UPPER[32 - RUS_UPPER.index(char)])
        elif char in RUS_LOWER:
            result.append(RUS_LOWER[32 - RUS_LOWER.index(char)])
        else:
            result.append(char)
    return ''.join(result)
# endregion

# region Современные алгоритмы хеширования
def encode_sha3_256(s):
    """
    Возвращает хеш SHA3-256 от строки s в шестнадцатеричном виде.
    """
    return hashlib.sha3_256(s.encode('utf-8')).hexdigest()

def encode_blake2b(s):
    """
    Возвращает хеш BLAKE2b от строки s в шестнадцатеричном виде.
    """
    return hashlib.blake2b(s.encode('utf-8')).hexdigest()
# endregion

class CipherApp(tk.Tk):
    """
    Основной класс приложения - графический интерфейс для кодирования и хеширования текста.
    Позволяет вводить текст и видеть результаты в реальном времени.
    """

    def __init__(self):
        super().__init__()
        self.title("Кодировщик")
        self.geometry("1000x750")

        # Переменные для параметров шифров
        self.xor_key = tk.StringVar(value='42')       # Ключ для XOR-шифра
        self.caesar_shift = tk.StringVar(value='3')   # Сдвиг для шифра Цезаря
        self.show_deprecated = tk.BooleanVar(value=False)  # Показывать ли устаревшие алгоритмы

        self.create_widgets()  # Создаем виджеты интерфейса
        self.setup_tags()      # Настраиваем стили для текста

    def create_widgets(self):
        """
        Создает и размещает все виджеты интерфейса: поля ввода параметров, текстовое поле ввода,
        область вывода результатов.
        """
        # Панель с параметрами шифров
        params_frame = ttk.Frame(self)
        params_frame.pack(fill='x', padx=10, pady=5)

        # Метка и поле для ключа XOR
        ttk.Label(params_frame, text="Ключ XOR:").grid(row=0, column=0, sticky='w')
        ttk.Entry(params_frame, textvariable=self.xor_key, width=5).grid(row=0, column=1, sticky='w')

        # Метка и поле для сдвига Цезаря
        ttk.Label(params_frame, text="Сдвиг Цезаря:").grid(row=0, column=2, padx=10, sticky='w')
        ttk.Entry(params_frame, textvariable=self.caesar_shift, width=5).grid(row=0, column=3, sticky='w')

        # Чекбокс для отображения устаревших алгоритмов
        ttk.Checkbutton(params_frame, text="Показывать устаревшие алгоритмы",
                        variable=self.show_deprecated).grid(row=0, column=4, padx=10, sticky='w')

        # Метка для поля ввода текста
        ttk.Label(self, text="Введите текст:", style='Input.TLabel').pack(anchor='w', padx=10)

        # Поле ввода текста
        self.entry_text = ttk.Entry(self, font=('Consolas', 14))
        self.entry_text.pack(fill='x', padx=10, pady=5)

        # Область вывода с полосой прокрутки
        self.output_area = scrolledtext.ScrolledText(self, state='disabled')
        self.output_area.pack(expand=True, fill='both', padx=10, pady=10)

        # Привязка события изменения текста к обработчику
        self.entry_text.bind('<KeyRelease>', self.on_text_change)

    def setup_tags(self):
        """
        Настраивает стили (теги) для текста в области вывода.
        Разные части текста будут окрашены в разные цвета.
        """
        style = ttk.Style()
        style.configure('Input.TLabel', foreground=COLORS['input_label'], font=('Arial', 12, 'bold'))

        tags_config = {
            'header': {'foreground': COLORS['header'], 'font': ('Consolas', 13, 'bold')},
            'label': {'foreground': COLORS['label'], 'font': ('Consolas', 12, 'bold')},
            'result': {'foreground': COLORS['result'], 'font': ('Consolas', 12)},
            'warning': {'foreground': COLORS['warning'], 'font': ('Consolas', 10, 'italic')}
        }

        for tag, config in tags_config.items():
            self.output_area.tag_configure(tag, **config)

    def on_text_change(self, event=None):
        """
        Обработчик события изменения текста в поле ввода.
        Запускает обновление результатов в отдельном потоке,
        чтобы не блокировать интерфейс.
        """
        text = self.entry_text.get()
        threading.Thread(target=self.safe_update_output, args=(text,), daemon=True).start()

    def safe_update_output(self, text):
        """
        Обновляет область вывода с результатами кодирования и хеширования.
        Выполняется в отдельном потоке, с защитой от ошибок.
        """
        try:
            # Разрешаем редактирование текстового поля
            self.output_area.config(state='normal')
            self.output_area.delete('1.0', tk.END)  # Очищаем предыдущий вывод

            # Формируем словарь с результатами
            results = {
                'Base64': base64.b64encode(text.encode()).decode(),
                'Base64 URL-safe': base64.urlsafe_b64encode(text.encode()).decode(),
                'SHA3-256': encode_sha3_256(text),
                'BLAKE2b': encode_blake2b(text),
                'Caesar': caesar_cipher(text, int(self.caesar_shift.get())),
                'Atbash': atbash_cipher(text),
                'XOR': self.xor_cipher(text)
            }

            # Добавляем устаревшие алгоритмы, если включено отображение
            if self.show_deprecated.get():
                results.update({
                    'MD5 (ненадежно!)': hashlib.md5(text.encode()).hexdigest(),
                    'SHA1 (ненадежно!)': hashlib.sha1(text.encode()).hexdigest()
                })

            # Выводим заголовок
            self.output_area.insert(tk.END, "----- РЕЗУЛЬТАТЫ -----\n", 'header')

            # Выводим результаты с форматированием
            for label, value in results.items():
                self.output_area.insert(tk.END, f"{label:20}", 'label')
                self.output_area.insert(tk.END, f"{value}\n", 'result')

            # Вывод предупреждений, если есть
            self.output_area.insert(tk.END, "\nПредупреждения:\n", 'header')
            self.check_warnings(text)

        except Exception as e:
            # При ошибках показываем окно с сообщением
            messagebox.showerror("Ошибка", f"Ошибка обработки: {str(e)}")
        finally:
            # Блокируем редактирование текстового поля
            self.output_area.config(state='disabled')

    def xor_cipher(self, s):
        """
        Применяет XOR-шифр к строке с указанным ключом.
        Возвращает результат в виде шестнадцатеричной строки.
        Если ключ некорректен, возвращает сообщение об ошибке.
        """
        try:
            key = int(self.xor_key.get())
            xored_bytes = bytes([b ^ key for b in s.encode()])
            return xored_bytes.hex()
        except ValueError:
            return "Некорректный ключ!"

    def check_warnings(self, text):
        """
        Проверяет текст на потенциальные проблемы и выводит предупреждения.
        Например, наличие буквы Ё или использование устаревших алгоритмов.
        """
        warnings = []
        if any(c in 'Ёё' for c in text):
            warnings.append("Обнаружены буквы Ё/ё - некоторые алгоритмы могут работать некорректно.")

        if self.show_deprecated.get():
            warnings.append("Используются устаревшие алгоритмы (MD5/SHA1) - не рекомендуется!")

        # Выводим каждое предупреждение в отдельной строке
        for warn in warnings:
            self.output_area.insert(tk.END, f"⚠ {warn}\n", 'warning')

if __name__ == "__main__":
    app = CipherApp()
    app.mainloop()
