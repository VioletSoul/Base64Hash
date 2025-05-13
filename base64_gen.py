import base64
import hashlib
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading

# Цвета для оформления интерфейса
COLORS = {
    'header': '#DAA520',       # Золотистый цвет для заголовков
    'label': '#1E90FF',        # Синий для названий алгоритмов
    'result': '#949494',       # Светло-серый для результатов кодирования
    'input_label': '#228B22',  # Зеленый для метки ввода
    'warning': '#FF4500'       # Оранжево-красный для предупреждений
}

def make_russian_alphabet():
    """
    Создаёт списки русских заглавных и строчных букв, включая букву Ё/ё,
    так как она не входит в непрерывный диапазон Unicode.
    """
    rus_upper = [chr(c) for c in range(ord('А'), ord('Е')+1)]  # А-Е
    rus_upper += ['Ё']                                         # Ё
    rus_upper += [chr(c) for c in range(ord('Ж'), ord('Я')+1)] # Ж-Я
    rus_lower = [c.lower() for c in rus_upper]                 # строчные буквы
    return rus_upper, rus_lower

# Глобальные списки алфавитов для шифров
RUS_UPPER, RUS_LOWER = make_russian_alphabet()
ENG_UPPER = [chr(c) for c in range(ord('A'), ord('Z')+1)]
ENG_LOWER = [chr(c) for c in range(ord('a'), ord('z')+1)]

def caesar_cipher(text, shift=3):
    """
    Шифр Цезаря с поддержкой русского и английского алфавитов.
    Сдвигает буквы на заданное число позиций, остальные символы не меняет.
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
            result.append(char)
    return ''.join(result)

def atbash_cipher(text):
    """
    Шифр Атбаш - замена буквы на "зеркальную" в алфавите.
    Поддерживает русский и английский алфавиты.
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

def encode_sha3_256(s):
    """
    Возвращает SHA3-256 хеш строки в шестнадцатеричном виде.
    """
    return hashlib.sha3_256(s.encode('utf-8')).hexdigest()

def encode_blake2b(s):
    """
    Возвращает BLAKE2b хеш строки в шестнадцатеричном виде.
    """
    return hashlib.blake2b(s.encode('utf-8')).hexdigest()

class CipherApp(tk.Tk):
    """
    Главное окно приложения с интерфейсом для ввода текста,
    выбора параметров и отображения результатов и предупреждений.
    """

    def __init__(self):
        super().__init__()
        self.title("Кодировщик")
        self.geometry("1000x750")

        # Переменные для параметров шифров
        self.xor_key = tk.StringVar(value='42')       # Ключ для XOR-шифра
        self.caesar_shift = tk.StringVar(value='3')   # Сдвиг для шифра Цезаря
        self.show_deprecated = tk.BooleanVar(value=False)  # Показывать устаревшие алгоритмы

        self.create_widgets()  # Создаём все виджеты интерфейса
        self.setup_tags()      # Настраиваем стили текста

    def create_widgets(self):
        """
        Создаёт и размещает вкладки и виджеты:
        - Вкладка с основным функционалом шифров и хешей
        - Вкладка с Base64 декодированием с двумя полями, разделёнными вертикально
        """
        # Создаём объект вкладок
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill='both')

        # Вкладка с основным функционалом шифров и хешей
        self.tab_cipher = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_cipher, text="Шифры и хеши")

        # Вкладка с Base64 декодированием
        self.tab_base64 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_base64, text="Base64 декодирование")

        # Заполняем вкладки соответствующими виджетами
        self.create_cipher_tab()
        self.create_base64_tab()

    def create_cipher_tab(self):
        """
        Создаёт интерфейс вкладки с шифрами и хешами:
        - Панель параметров (ключ XOR, сдвиг Цезаря, чекбокс устаревших алгоритмов)
        - Поле ввода текста
        - Метка и область вывода результатов
        - Метка и область вывода предупреждений
        """
        # Панель параметров
        params_frame = ttk.Frame(self.tab_cipher)
        params_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(params_frame, text="Ключ XOR:").grid(row=0, column=0, sticky='w')
        ttk.Entry(params_frame, textvariable=self.xor_key, width=5).grid(row=0, column=1, sticky='w')

        ttk.Label(params_frame, text="Сдвиг Цезаря:").grid(row=0, column=2, padx=10, sticky='w')
        ttk.Entry(params_frame, textvariable=self.caesar_shift, width=5).grid(row=0, column=3, sticky='w')

        ttk.Checkbutton(params_frame, text="Показывать устаревшие алгоритмы",
                        variable=self.show_deprecated).grid(row=0, column=4, padx=10, sticky='w')

        # Метка для поля ввода текста
        ttk.Label(self.tab_cipher, text="Введите текст:", style='Input.TLabel').pack(anchor='w', padx=10)

        # Многострочное поле ввода текста с прокруткой
        self.entry_text = scrolledtext.ScrolledText(self.tab_cipher, font=('Consolas', 14), height=6)
        self.entry_text.pack(fill='x', padx=10, pady=5)

        # Метка над областью вывода результатов
        ttk.Label(self.tab_cipher, text="Результаты:", style='Output.TLabel').pack(anchor='w', padx=10)

        # Область вывода результатов с прокруткой (только для чтения)
        self.output_area = scrolledtext.ScrolledText(self.tab_cipher, state='disabled')
        self.output_area.pack(expand=True, fill='both', padx=10, pady=10)

        # Метка над областью предупреждений
        ttk.Label(self.tab_cipher, text="Предупреждения:", style='Warning.TLabel').pack(anchor='w', padx=10)

        # Область предупреждений с прокруткой (только для чтения)
        self.warnings_area = scrolledtext.ScrolledText(self.tab_cipher, height=6, state='disabled', foreground=COLORS['warning'])
        self.warnings_area.pack(fill='x', padx=10, pady=(0,10))

        # Привязываем обработчик изменения текста для запуска обновления результатов
        self.entry_text.bind('<KeyRelease>', self.on_text_change)

    def create_base64_tab(self):
        """
        Создаёт интерфейс вкладки Base64 декодирования:
        - Два многострочных текстовых поля, разделённых горизонтально
          (слева - ввод Base64, справа - декодированный текст)
        - Метки над каждым полем
        """
        # Основной фрейм для двух областей
        main_frame = ttk.Frame(self.tab_base64)
        main_frame.pack(expand=True, fill='both', padx=10, pady=10)

        # Левая часть: ввод Base64 для декодирования
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='top', fill='both', expand=True, pady=(0,5))

        ttk.Label(left_frame, text="Base64 код:", style='Input.TLabel').pack(anchor='w')
        self.base64_encode_input = scrolledtext.ScrolledText(left_frame, font=('Consolas', 12), height=15)
        self.base64_encode_input.pack(expand=True, fill='both')

        # Правая часть: вывод декодированного текста
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='top', fill='both', expand=True)

        ttk.Label(right_frame, text="Декодированный текст:", style='Output.TLabel').pack(anchor='w')
        self.base64_decode_output = scrolledtext.ScrolledText(right_frame, font=('Consolas', 12), height=15, state='disabled')
        self.base64_decode_output.pack(expand=True, fill='both')

        # Привязываем обработчик для автоматического декодирования при вводе
        self.base64_encode_input.bind('<KeyRelease>', self.on_base64_encode_change)

    def setup_tags(self):
        """
        Настраивает стили (теги) для текста и меток в интерфейсе.
        """
        style = ttk.Style()
        style.configure('Input.TLabel', foreground=COLORS['input_label'], font=('Arial', 12, 'bold'))
        style.configure('Output.TLabel', foreground=COLORS['header'], font=('Arial', 12, 'bold'))
        style.configure('Warning.TLabel', foreground=COLORS['warning'], font=('Arial', 12, 'bold'))

        tags_config = {
            'label': {'foreground': COLORS['label'], 'font': ('Consolas', 12, 'bold')},
            'result': {'foreground': COLORS['result'], 'font': ('Consolas', 12)},
            'warning': {'foreground': COLORS['warning'], 'font': ('Consolas', 10, 'italic')}
        }

        for tag, config in tags_config.items():
            self.output_area.tag_configure(tag, **config)

    def on_text_change(self, event=None):
        """
        Обработчик изменения текста в поле ввода основной вкладки.
        Запускает вычисления в отдельном потоке для отзывчивости интерфейса.
        """
        text = self.entry_text.get('1.0', 'end-1c')
        threading.Thread(target=self.compute_results_thread, args=(text,), daemon=True).start()

    def compute_results_thread(self, text):
        """
        Выполняет вычисления шифров и хешей в отдельном потоке.
        Формирует результаты и предупреждения, затем обновляет интерфейс.
        """
        results = {}
        warnings = []

        # Проверка корректности сдвига Цезаря
        try:
            shift = int(self.caesar_shift.get())
        except ValueError:
            shift = None
            warnings.append("Сдвиг Цезаря должен быть целым числом!")

        # Проверка корректности ключа XOR
        try:
            xor_key = int(self.xor_key.get())
            if not (0 <= xor_key <= 255):
                warnings.append("Ключ XOR должен быть в диапазоне 0-255!")
                xor_key = None
        except ValueError:
            warnings.append("Ключ XOR должен быть целым числом!")
            xor_key = None

        try:
            # Вычисление основных кодировок и хешей
            results['Base64'] = base64.b64encode(text.encode()).decode()
            results['Base64 URL-safe'] = base64.urlsafe_b64encode(text.encode()).decode()
            results['SHA3-256'] = encode_sha3_256(text)
            results['BLAKE2b'] = encode_blake2b(text)

            # Шифр Цезаря с проверкой
            if shift is not None:
                results['Caesar'] = caesar_cipher(text, shift)
            else:
                results['Caesar'] = "Ошибка сдвига!"

            # Шифр Атбаш
            results['Atbash'] = atbash_cipher(text)

            # XOR-шифр с проверкой
            if xor_key is not None:
                results['XOR'] = self.xor_cipher(text, xor_key)
            else:
                results['XOR'] = "Ошибка ключа XOR!"

            # Устаревшие алгоритмы, если включены
            if self.show_deprecated.get():
                results['MD5 (ненадежно!)'] = hashlib.md5(text.encode()).hexdigest()
                results['SHA1 (ненадежно!)'] = hashlib.sha1(text.encode()).hexdigest()

            # Предупреждения по содержимому текста
            if any(c in 'Ёё' for c in text):
                warnings.append("Обнаружены буквы Ё/ё - некоторые алгоритмы могут работать некорректно.")

            if self.show_deprecated.get():
                warnings.append("Используются устаревшие алгоритмы (MD5/SHA1) - не рекомендуется!")

        except Exception as e:
            warnings.append(f"Ошибка обработки данных: {str(e)}")

        # Обновляем интерфейс в главном потоке
        self.after(0, self.update_output_area, results, warnings)

    def update_output_area(self, results, warnings):
        """
        Обновляет области вывода результатов и предупреждений.
        """
        # Обновляем результаты
        self.output_area.config(state='normal')
        self.output_area.delete('1.0', tk.END)

        for label, value in results.items():
            self.output_area.insert(tk.END, f"{label:20}", 'label')
            self.output_area.insert(tk.END, f"{value}\n", 'result')
        self.output_area.config(state='disabled')

        # Обновляем предупреждения
        self.warnings_area.config(state='normal')
        self.warnings_area.delete('1.0', tk.END)
        if warnings:
            for warn in warnings:
                self.warnings_area.insert(tk.END, f"⚠ {warn}\n")
        self.warnings_area.config(state='disabled')

    def xor_cipher(self, s, key):
        """
        Применяет XOR-шифр к строке с указанным ключом.
        Возвращает результат в виде шестнадцатеричной строки.
        """
        xored_bytes = bytes([b ^ key for b in s.encode()])
        return xored_bytes.hex()

    def on_base64_encode_change(self, event=None):
        """
        Обработчик изменения текста в поле Base64 декодирования.
        Пытается декодировать Base64 и выводит результат в соседнем поле.
        При ошибке выводит сообщение об ошибке.
        """
        encoded_text = self.base64_encode_input.get('1.0', 'end-1c').strip()
        if not encoded_text:
            # Если поле пустое, очищаем вывод
            self.base64_decode_output.config(state='normal')
            self.base64_decode_output.delete('1.0', tk.END)
            self.base64_decode_output.config(state='disabled')
            return

        try:
            # Пытаемся декодировать Base64 с проверкой валидности
            decoded_bytes = base64.b64decode(encoded_text, validate=True)
            # Декодируем байты в строку UTF-8, заменяя некорректные символы
            decoded_str = decoded_bytes.decode('utf-8', errors='replace')
        except Exception:
            decoded_str = "[Ошибка: некорректный Base64]"

        # Обновляем поле вывода декодированного текста
        self.base64_decode_output.config(state='normal')
        self.base64_decode_output.delete('1.0', tk.END)
        self.base64_decode_output.insert(tk.END, decoded_str)
        self.base64_decode_output.config(state='disabled')

if __name__ == "__main__":
    app = CipherApp()
    app.mainloop()
