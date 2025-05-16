import base64
import hashlib
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import random
import string

# Color scheme for UI elements
COLORS = {
    'header': '#DAA520',       # Golden color for headers
    'label': '#1E90FF',        # Blue for algorithm labels
    'result': '#949494',       # Light gray for results
    'input_label': '#228B22',  # Green for input labels
    'warning': '#FF4500'       # Orange-red for warnings
}

# ================== MULTILANGUAGE SUPPORT ==================
LANGUAGES = {
    'ru': {
        'app_title': 'Base64+ Encoder',
        'tabs': ['Ciphers & Encoding', 'Base64 Decoding', 'SHA3-256 Hashing',
                 'BLAKE2b Hashing', 'Password Generator'],
        'labels': {
            'input_text': 'Enter text:',
            'results': 'Results:',
            'warnings': 'Warnings:',
            'password_length': 'Password length:',
            'generate_password': 'Generate',
            'copy_password': 'Copy',
            'charsets': {
                'letters': 'Letters',
                'digits': 'Digits',
                'symbols': 'Symbols'
            },
            'language_menu': '🌐 Language',
            'language_ru': 'Russian',
            'language_en': 'English',
            'error_select_charset': 'Select at least one character set!',
            'error_invalid_length': 'Invalid password length!',
            'copied': 'Password copied to clipboard!',
            'xor_key': 'XOR Key:',
            'caesar_shift': 'Caesar Shift:',
            'show_deprecated': 'Show deprecated algorithms'
        }
    },
    'en': {
        'app_title': 'Base64+ Encoder',
        'tabs': ['Ciphers & Encoding', 'Base64 Decoding', 'SHA3-256 Hashing',
                 'BLAKE2b Hashing', 'Password Generator'],
        'labels': {
            'input_text': 'Input text:',
            'results': 'Results:',
            'warnings': 'Warnings:',
            'password_length': 'Password length:',
            'generate_password': 'Generate',
            'copy_password': 'Copy',
            'charsets': {
                'letters': 'Letters',
                'digits': 'Digits',
                'symbols': 'Symbols'
            },
            'language_menu': '🌐 Language',
            'language_ru': 'Russian',
            'language_en': 'English',
            'error_select_charset': 'Select at least one character set!',
            'error_invalid_length': 'Invalid password length!',
            'copied': 'Password copied to clipboard!',
            'xor_key': 'XOR Key:',
            'caesar_shift': 'Caesar Shift:',
            'show_deprecated': 'Show deprecated algorithms'
        }
    }
}

def make_russian_alphabet():
    """
    Creates lists of Russian uppercase and lowercase letters,
    including the letter Ё/ё which is outside the continuous Unicode range.
    Returns two lists: uppercase letters and lowercase letters.
    """
    rus_upper = [chr(c) for c in range(ord('А'), ord('Е')+1)]  # А-Е
    rus_upper += ['Ё']                                         # Ё
    rus_upper += [chr(c) for c in range(ord('Ж'), ord('Я')+1)] # Ж-Я
    rus_lower = [c.lower() for c in rus_upper]                 # lowercase letters
    return rus_upper, rus_lower

# Global alphabets for ciphers
RUS_UPPER, RUS_LOWER = make_russian_alphabet()
ENG_UPPER = [chr(c) for c in range(ord('A'), ord('Z')+1)]
ENG_LOWER = [chr(c) for c in range(ord('a'), ord('z')+1)]

def caesar_cipher(text, shift=3):
    """
    Applies the Caesar cipher to the input text with the given shift.
    Supports both Russian and English alphabets, including Ё/ё.
    Non-alphabetic characters remain unchanged.
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
            # Non-alphabetic characters are not changed
            result.append(char)
    return ''.join(result)

def atbash_cipher(text):
    """
    Implements the Atbash cipher - replaces each letter with its "mirror" counterpart in the alphabet.
    Supports Russian and English alphabets including Ё/ё.
    Non-alphabetic characters remain unchanged.
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
    Returns the SHA3-256 hash of the input string in hexadecimal format.
    """
    return hashlib.sha3_256(s.encode('utf-8')).hexdigest()

def encode_blake2b(s):
    """
    Returns the BLAKE2b hash of the input string in hexadecimal format.
    """
    return hashlib.blake2b(s.encode('utf-8')).hexdigest()

class I18N:
    """Class for localization management"""
    def __init__(self, language='ru'):
        self.language = language
        self.strings = LANGUAGES.get(language, LANGUAGES['ru'])

    def set_language(self, lang):
        self.language = lang
        self.strings = LANGUAGES.get(lang, LANGUAGES['ru'])

class CipherApp(tk.Tk):
    """
    Main application window class.
    Provides a tabbed interface for encoding, encryption, hashing text,
    and a password generator with multilingual support.
    """

    def __init__(self):
        super().__init__()

        # Initialize localization
        self.i18n = I18N()

        # Set the window title
        self.title(self.i18n.strings['app_title'])

        # Set the window size
        self.geometry("1000x750")

        # Variables for cipher parameters
        self.xor_key = tk.StringVar(value='42')       # XOR cipher key (integer 0-255)
        self.caesar_shift = tk.StringVar(value='3')   # Caesar cipher shift (integer)
        self.show_deprecated = tk.BooleanVar(value=False)  # Whether to show deprecated algorithms (MD5, SHA1)

        # Initialize UI components
        self.create_language_menu()
        self.create_widgets()
        self.setup_tags()

    def create_language_menu(self):
        """Creates the language selection menu"""
        menubar = tk.Menu(self)
        lang_menu = tk.Menu(menubar, tearoff=0)
        lang_menu.add_command(label=self.i18n.strings['labels']['language_ru'], command=lambda: self.change_language('ru'))
        lang_menu.add_command(label=self.i18n.strings['labels']['language_en'], command=lambda: self.change_language('en'))
        menubar.add_cascade(label=self.i18n.strings['labels']['language_menu'], menu=lang_menu)
        self.config(menu=menubar)

    def change_language(self, lang):
        """Changes the interface language"""
        self.i18n.set_language(lang)
        self.title(self.i18n.strings['app_title'])

        # Update tab titles
        for i, title in enumerate(self.i18n.strings['tabs']):
            self.notebook.tab(i, text=title)

        # Update language menu (to translate items)
        self.create_language_menu()

        # Update other interface elements
        self.update_all_labels()

    def update_all_labels(self):
        """Updates all text labels in the interface"""

        # Ciphers and Encoding tab
        self.label_input_text.config(text=self.i18n.strings['labels']['input_text'])
        self.label_results.config(text=self.i18n.strings['labels']['results'])
        self.label_warnings.config(text=self.i18n.strings['labels']['warnings'])

        self.label_xor_key.config(text=self.i18n.strings['labels']['xor_key'])
        self.label_caesar_shift.config(text=self.i18n.strings['labels']['caesar_shift'])
        self.checkbox_deprecated.config(text=self.i18n.strings['labels']['show_deprecated'])

        # Base64 tab
        self.label_base64_input.config(text=self.i18n.strings['labels']['input_text'])
        self.label_base64_output.config(text=self.i18n.strings['labels']['results'])

        # SHA3-256 tab
        self.label_sha3_input.config(text=self.i18n.strings['labels']['input_text'])
        self.label_sha3_output.config(text=self.i18n.strings['labels']['results'])

        # BLAKE2b tab
        self.label_blake2b_input.config(text=self.i18n.strings['labels']['input_text'])
        self.label_blake2b_output.config(text=self.i18n.strings['labels']['results'])

        # Password generator tab
        self.label_pwd_length.config(text=self.i18n.strings['labels']['password_length'])
        self.checkbox_letters.config(text=self.i18n.strings['labels']['charsets']['letters'])
        self.checkbox_digits.config(text=self.i18n.strings['labels']['charsets']['digits'])
        self.checkbox_symbols.config(text=self.i18n.strings['labels']['charsets']['symbols'])
        self.btn_generate.config(text=self.i18n.strings['labels']['generate_password'])
        self.btn_copy.config(text=self.i18n.strings['labels']['copy_password'])

    def create_widgets(self):
        """
        Create and place all widgets including the tab control and content of each tab.
        """
        # Create the notebook (tab container)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill='both')

        # Tab 1: Encoding and ciphers (no hashing)
        self.tab_cipher = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_cipher, text=self.i18n.strings['tabs'][0])  # "Ciphers and Encoding"

        # Tab 2: Base64 decoding
        self.tab_base64 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_base64, text=self.i18n.strings['tabs'][1])  # "Base64 Decoding"

        # Tab 3: SHA3-256 hashing
        self.tab_sha3 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_sha3, text=self.i18n.strings['tabs'][2])  # "SHA3-256 Hashing"

        # Tab 4: BLAKE2b hashing
        self.tab_blake2b = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_blake2b, text=self.i18n.strings['tabs'][3])  # "BLAKE2b Hashing"

        # Tab 5: Password generator
        self.tab_password = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_password, text=self.i18n.strings['tabs'][4])  # "Password Generator"

        # Populate each tab with its widgets
        self.create_cipher_tab()
        self.create_base64_tab()
        self.create_sha3_tab()
        self.create_blake2b_tab()
        self.create_password_generator_tab()

    def create_cipher_tab(self):
        """
        Create the interface for the 'Ciphers and Encoding' tab:
        - Parameters panel for XOR key, Caesar shift, and deprecated algorithms checkbox
        - Text input area
        - Results display area (encoding and ciphers only)
        - Warnings display area
        """
        # Frame for parameters input
        params_frame = ttk.Frame(self.tab_cipher)
        params_frame.pack(fill='x', padx=10, pady=5)

        # XOR key label and entry
        self.label_xor_key = ttk.Label(params_frame, text=self.i18n.strings['labels']['xor_key'])
        self.label_xor_key.grid(row=0, column=0, sticky='w')
        ttk.Entry(params_frame, textvariable=self.xor_key, width=5).grid(row=0, column=1, sticky='w')

        # Caesar shift label and entry
        self.label_caesar_shift = ttk.Label(params_frame, text=self.i18n.strings['labels']['caesar_shift'])
        self.label_caesar_shift.grid(row=0, column=2, padx=10, sticky='w')
        ttk.Entry(params_frame, textvariable=self.caesar_shift, width=5).grid(row=0, column=3, sticky='w')

        # Checkbox for deprecated algorithms
        self.checkbox_deprecated = ttk.Checkbutton(params_frame, text=self.i18n.strings['labels']['show_deprecated'],
                                                   variable=self.show_deprecated)
        self.checkbox_deprecated.grid(row=0, column=4, padx=10, sticky='w')

        # Label for text input
        self.label_input_text = ttk.Label(self.tab_cipher, text=self.i18n.strings['labels']['input_text'], style='Input.TLabel')
        self.label_input_text.pack(anchor='w', padx=10)

        # Text input area with scrollbar
        self.entry_text = scrolledtext.ScrolledText(self.tab_cipher, font=('Consolas', 14), height=6)
        self.entry_text.pack(fill='x', padx=10, pady=5)

        # Label for results
        self.label_results = ttk.Label(self.tab_cipher, text=self.i18n.strings['labels']['results'], style='Output.TLabel')
        self.label_results.pack(anchor='w', padx=10)

        # Results display area (readonly)
        self.output_area = scrolledtext.ScrolledText(self.tab_cipher, state='disabled')
        self.output_area.pack(expand=True, fill='both', padx=10, pady=10)

        # Label for warnings
        self.label_warnings = ttk.Label(self.tab_cipher, text=self.i18n.strings['labels']['warnings'], style='Warning.TLabel')
        self.label_warnings.pack(anchor='w', padx=10)

        # Warnings display area (readonly)
        self.warnings_area = scrolledtext.ScrolledText(self.tab_cipher, height=6, state='disabled', foreground=COLORS['warning'])
        self.warnings_area.pack(fill='x', padx=10, pady=(0, 10))

        # Bind text change event to update results
        self.entry_text.bind('<KeyRelease>', self.on_text_change)

    def create_base64_tab(self):
        """
        Create the interface for the 'Base64 Decoding' tab:
        - Two vertically stacked text areas:
          - Top: Base64 input
          - Bottom: Decoded text output
        - Labels for each area
        """
        main_frame = ttk.Frame(self.tab_base64)
        main_frame.pack(expand=True, fill='both', padx=10, pady=10)

        # Top frame for Base64 input
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(side='top', fill='both', expand=True, pady=(0, 5))

        self.label_base64_input = ttk.Label(top_frame, text=self.i18n.strings['labels']['input_text'], style='Input.TLabel')
        self.label_base64_input.pack(anchor='w')
        self.base64_encode_input = scrolledtext.ScrolledText(top_frame, font=('Consolas', 12), height=15)
        self.base64_encode_input.pack(expand=True, fill='both')

        # Bottom frame for decoded output
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(side='top', fill='both', expand=True)

        self.label_base64_output = ttk.Label(bottom_frame, text=self.i18n.strings['labels']['results'], style='Output.TLabel')
        self.label_base64_output.pack(anchor='w')
        self.base64_decode_output = scrolledtext.ScrolledText(bottom_frame, font=('Consolas', 12), height=15, state='disabled')
        self.base64_decode_output.pack(expand=True, fill='both')

        # Bind text change event for decoding Base64 input
        self.base64_encode_input.bind('<KeyRelease>', self.on_base64_encode_change)

    def create_sha3_tab(self):
        """
        Create the interface for the 'SHA3-256 Hashing' tab:
        - Top text area for input
        - Bottom text area for hash output
        - Labels for each area
        """
        main_frame = ttk.Frame(self.tab_sha3)
        main_frame.pack(expand=True, fill='both', padx=10, pady=10)

        # Top frame for input
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(side='top', fill='both', expand=True, pady=(0, 5))

        self.label_sha3_input = ttk.Label(top_frame, text=self.i18n.strings['labels']['input_text'], style='Input.TLabel')
        self.label_sha3_input.pack(anchor='w')
        self.sha3_input = scrolledtext.ScrolledText(top_frame, font=('Consolas', 12), height=15)
        self.sha3_input.pack(expand=True, fill='both')

        # Bottom frame for output
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(side='top', fill='both', expand=True)

        self.label_sha3_output = ttk.Label(bottom_frame, text=self.i18n.strings['labels']['results'], style='Output.TLabel')
        self.label_sha3_output.pack(anchor='w')
        self.sha3_output = scrolledtext.ScrolledText(bottom_frame, font=('Consolas', 12), height=15, state='disabled')
        self.sha3_output.pack(expand=True, fill='both')

        # Bind text change event to update hash
        self.sha3_input.bind('<KeyRelease>', self.on_sha3_input_change)

    def create_blake2b_tab(self):
        """
        Create the interface for the 'BLAKE2b Hashing' tab:
        - Top text area for input
        - Bottom text area for hash output
        - Labels for each area
        """
        main_frame = ttk.Frame(self.tab_blake2b)
        main_frame.pack(expand=True, fill='both', padx=10, pady=10)

        # Top frame for input
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(side='top', fill='both', expand=True, pady=(0, 5))

        self.label_blake2b_input = ttk.Label(top_frame, text=self.i18n.strings['labels']['input_text'], style='Input.TLabel')
        self.label_blake2b_input.pack(anchor='w')
        self.blake2b_input = scrolledtext.ScrolledText(top_frame, font=('Consolas', 12), height=15)
        self.blake2b_input.pack(expand=True, fill='both')

        # Bottom frame for output
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(side='top', fill='both', expand=True)

        self.label_blake2b_output = ttk.Label(bottom_frame, text=self.i18n.strings['labels']['results'], style='Output.TLabel')
        self.label_blake2b_output.pack(anchor='w')
        self.blake2b_output = scrolledtext.ScrolledText(bottom_frame, font=('Consolas', 12), height=15, state='disabled')
        self.blake2b_output.pack(expand=True, fill='both')

        # Bind text change event to update hash
        self.blake2b_input.bind('<KeyRelease>', self.on_blake2b_input_change)

    def create_password_generator_tab(self):
        """Creates the password generator tab"""
        main_frame = ttk.Frame(self.tab_password)
        main_frame.pack(expand=True, fill='both', padx=10, pady=10)

        # Password settings
        settings_frame = ttk.Frame(main_frame)
        settings_frame.pack(pady=10)

        self.label_pwd_length = ttk.Label(settings_frame, text=self.i18n.strings['labels']['password_length'])
        self.label_pwd_length.grid(row=0, column=0, sticky='w')
        self.pwd_length = ttk.Spinbox(settings_frame, from_=4, to=64, width=5)
        self.pwd_length.grid(row=0, column=1, padx=5)
        self.pwd_length.set(12)

        # Checkboxes for character selection
        self.use_letters = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=False)

        self.checkbox_letters = ttk.Checkbutton(settings_frame,
                                                text=self.i18n.strings['labels']['charsets']['letters'],
                                                variable=self.use_letters)
        self.checkbox_letters.grid(row=1, column=0, sticky='w')
        self.checkbox_digits = ttk.Checkbutton(settings_frame,
                                               text=self.i18n.strings['labels']['charsets']['digits'],
                                               variable=self.use_digits)
        self.checkbox_digits.grid(row=1, column=1, sticky='w')
        self.checkbox_symbols = ttk.Checkbutton(settings_frame,
                                                text=self.i18n.strings['labels']['charsets']['symbols'],
                                                variable=self.use_symbols)
        self.checkbox_symbols.grid(row=1, column=2, sticky='w')

        # Buttons for generating and copying
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=5)

        self.btn_generate = ttk.Button(btn_frame,
                                       text=self.i18n.strings['labels']['generate_password'],
                                       command=self.generate_password)
        self.btn_generate.pack(side='left', padx=5)
        self.btn_copy = ttk.Button(btn_frame,
                                   text=self.i18n.strings['labels']['copy_password'],
                                   command=self.copy_password)
        self.btn_copy.pack(side='left', padx=5)

        # Password output field
        self.password_output = ttk.Entry(main_frame,
                                        font=('Consolas', 14),
                                        width=30,
                                        justify='center')
        self.password_output.pack(pady=10)

    def setup_tags(self):
        """
        Configure text styles (tags) for different parts of the output areas.
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
        Event handler for text changes in the encoding and cipher tab input.
        Starts a background thread to compute results without freezing the UI.
        """
        text = self.entry_text.get('1.0', 'end-1c')
        threading.Thread(target=self.compute_results_thread, args=(text,), daemon=True).start()

    def compute_results_thread(self, text):
        """
        Performs encoding and cipher computations in a separate thread.
        Collects results and warnings, then updates the UI safely in the main thread.
        """
        results = {}
        warnings = []

        # Validate Caesar cipher shift
        try:
            shift = int(self.caesar_shift.get())
        except ValueError:
            shift = None
            warnings.append("Caesar shift must be an integer!")

        # Validate XOR key
        try:
            xor_key = int(self.xor_key.get())
            if not (0 <= xor_key <= 255):
                warnings.append("XOR key must be in the range 0-255!")
                xor_key = None
        except ValueError:
            warnings.append("XOR key must be an integer!")
            xor_key = None

        try:
            # Compute encodings (excluding hashes)
            results['Base64'] = base64.b64encode(text.encode()).decode()
            results['Base64 URL-safe'] = base64.urlsafe_b64encode(text.encode()).decode()

            # Caesar cipher result or error message
            if shift is not None:
                results['Caesar'] = caesar_cipher(text, shift)
            else:
                results['Caesar'] = "Shift error!"

            # Atbash cipher
            results['Atbash'] = atbash_cipher(text)

            # XOR cipher result or error message
            if xor_key is not None:
                results['XOR'] = self.xor_cipher(text, xor_key)
            else:
                results['XOR'] = "XOR key error!"

            # Deprecated algorithms if enabled
            if self.show_deprecated.get():
                results['MD5 (deprecated)'] = hashlib.md5(text.encode()).hexdigest()
                results['SHA1 (deprecated)'] = hashlib.sha1(text.encode()).hexdigest()

            # Warnings for special characters
            if any(c in 'Ёё' for c in text):
                warnings.append("Detected letters Ё/ё - some algorithms may behave incorrectly.")

            if self.show_deprecated.get():
                warnings.append("Deprecated algorithms (MD5/SHA1) are used - not recommended!")

        except Exception as e:
            warnings.append(f"Data processing error: {str(e)}")

        # Update UI in the main thread
        self.after(0, self.update_output_area, results, warnings)

    def update_output_area(self, results, warnings):
        """
        Updates the results and warnings text areas with new data.
        """
        # Update results area
        self.output_area.config(state='normal')
        self.output_area.delete('1.0', tk.END)

        for label, value in results.items():
            self.output_area.insert(tk.END, f"{label:20}", 'label')
            self.output_area.insert(tk.END, f"{value}\n", 'result')
        self.output_area.config(state='disabled')

        # Update warnings area
        self.warnings_area.config(state='normal')
        self.warnings_area.delete('1.0', tk.END)
        if warnings:
            for warn in warnings:
                self.warnings_area.insert(tk.END, f"⚠ {warn}\n")
        self.warnings_area.config(state='disabled')

    def xor_cipher(self, s, key):
        """
        Applies XOR cipher to the input string with the specified key.
        Returns the result as a hexadecimal string.
        """
        xored_bytes = bytes([b ^ key for b in s.encode()])
        return xored_bytes.hex()

    def on_base64_encode_change(self, event=None):
        """
        Event handler for changes in the Base64 input field.
        Attempts to decode Base64 and updates the output field.
        Displays an error message if decoding fails.
        """
        encoded_text = self.base64_encode_input.get('1.0', 'end-1c').strip()
        if not encoded_text:
            # Clear output if input is empty
            self.base64_decode_output.config(state='normal')
            self.base64_decode_output.delete('1.0', tk.END)
            self.base64_decode_output.config(state='disabled')
            return

        try:
            # Decode Base64 with validation
            decoded_bytes = base64.b64decode(encoded_text, validate=True)
            decoded_str = decoded_bytes.decode('utf-8', errors='replace')
        except Exception:
            decoded_str = "[Error: Invalid Base64]"

        # Update decoded text output
        self.base64_decode_output.config(state='normal')
        self.base64_decode_output.delete('1.0', tk.END)
        self.base64_decode_output.insert(tk.END, decoded_str)
        self.base64_decode_output.config(state='disabled')

    def on_sha3_input_change(self, event=None):
        """
        Event handler for changes in the SHA3-256 input field.
        Automatically computes the SHA3-256 hash and updates the output field.
        """
        text = self.sha3_input.get('1.0', 'end-1c')
        if not text:
            self.sha3_output.config(state='normal')
            self.sha3_output.delete('1.0', tk.END)
            self.sha3_output.config(state='disabled')
            return

        hash_value = encode_sha3_256(text)

        self.sha3_output.config(state='normal')
        self.sha3_output.delete('1.0', tk.END)
        self.sha3_output.insert(tk.END, hash_value)
        self.sha3_output.config(state='disabled')

    def on_blake2b_input_change(self, event=None):
        """
        Event handler for changes in the BLAKE2b input field.
        Automatically computes the BLAKE2b hash and updates the output field.
        """
        text = self.blake2b_input.get('1.0', 'end-1c')
        if not text:
            self.blake2b_output.config(state='normal')
            self.blake2b_output.delete('1.0', tk.END)
            self.blake2b_output.config(state='disabled')
            return

        hash_value = encode_blake2b(text)

        self.blake2b_output.config(state='normal')
        self.blake2b_output.delete('1.0', tk.END)
        self.blake2b_output.insert(tk.END, hash_value)
        self.blake2b_output.config(state='disabled')

    # ===== Password Generator =====
    def generate_password(self):
        """Generates a password based on selected parameters"""
        charset = ''
        if self.use_letters.get():
            charset += string.ascii_letters
        if self.use_digits.get():
            charset += string.digits
        if self.use_symbols.get():
            charset += string.punctuation

        if not charset:
            messagebox.showerror("Error", self.i18n.strings['labels']['error_select_charset'])
            return

        try:
            length = int(self.pwd_length.get())
            password = ''.join(random.choices(charset, k=length))
            self.password_output.delete(0, tk.END)
            self.password_output.insert(0, password)
        except ValueError:
            messagebox.showerror("Error", self.i18n.strings['labels']['error_invalid_length'])

    def copy_password(self):
        """Copies the password to the clipboard"""
        self.clipboard_clear()
        self.clipboard_append(self.password_output.get())
        messagebox.showinfo("Info", self.i18n.strings['labels']['copied'])


if __name__ == "__main__":
    app = CipherApp()
    app.mainloop()
