import base64
import hashlib
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading

# Color scheme for UI elements
COLORS = {
    'header': '#DAA520',       # Golden color for headers
    'label': '#1E90FF',        # Blue for algorithm labels
    'result': '#949494',       # Light gray for results
    'input_label': '#228B22',  # Green for input labels
    'warning': '#FF4500'       # Orange-red for warnings
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

class CipherApp(tk.Tk):
    """
    Main application window class.
    Provides a tabbed interface for encoding, encryption, and hashing text.
    """

    def __init__(self):
        super().__init__()

        # Set the window title
        self.title("Base64+ кодировщик")

        # Set the window size
        self.geometry("1000x750")

        # Variables for cipher parameters
        self.xor_key = tk.StringVar(value='42')       # XOR cipher key (integer 0-255)
        self.caesar_shift = tk.StringVar(value='3')   # Caesar cipher shift (integer)
        self.show_deprecated = tk.BooleanVar(value=False)  # Whether to show deprecated algorithms (MD5, SHA1)

        # Initialize UI components
        self.create_widgets()
        self.setup_tags()

    def create_widgets(self):
        """
        Create and place all widgets including the tab control and content of each tab.
        """
        # Create the notebook (tab container)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill='both')

        # Tab 1: Encoding and ciphers (no hashing)
        self.tab_cipher = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_cipher, text="Шифры и кодирование")  # "Ciphers and Encoding"

        # Tab 2: Base64 decoding
        self.tab_base64 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_base64, text="Base64 декодирование")  # "Base64 Decoding"

        # Tab 3: SHA3-256 hashing
        self.tab_sha3 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_sha3, text="SHA3-256 хеширование")  # "SHA3-256 Hashing"

        # Tab 4: BLAKE2b hashing
        self.tab_blake2b = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_blake2b, text="BLAKE2b хеширование")  # "BLAKE2b Hashing"

        # Populate each tab with its widgets
        self.create_cipher_tab()
        self.create_base64_tab()
        self.create_sha3_tab()
        self.create_blake2b_tab()

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
        ttk.Label(params_frame, text="Ключ XOR:").grid(row=0, column=0, sticky='w')
        ttk.Entry(params_frame, textvariable=self.xor_key, width=5).grid(row=0, column=1, sticky='w')

        # Caesar shift label and entry
        ttk.Label(params_frame, text="Сдвиг Цезаря:").grid(row=0, column=2, padx=10, sticky='w')
        ttk.Entry(params_frame, textvariable=self.caesar_shift, width=5).grid(row=0, column=3, sticky='w')

        # Checkbox for deprecated algorithms
        ttk.Checkbutton(params_frame, text="Показывать устаревшие алгоритмы",
                        variable=self.show_deprecated).grid(row=0, column=4, padx=10, sticky='w')

        # Label for text input
        ttk.Label(self.tab_cipher, text="Введите текст:", style='Input.TLabel').pack(anchor='w', padx=10)

        # Text input area with scrollbar
        self.entry_text = scrolledtext.ScrolledText(self.tab_cipher, font=('Consolas', 14), height=6)
        self.entry_text.pack(fill='x', padx=10, pady=5)

        # Label for results
        ttk.Label(self.tab_cipher, text="Результаты:", style='Output.TLabel').pack(anchor='w', padx=10)

        # Results display area (readonly)
        self.output_area = scrolledtext.ScrolledText(self.tab_cipher, state='disabled')
        self.output_area.pack(expand=True, fill='both', padx=10, pady=10)

        # Label for warnings
        ttk.Label(self.tab_cipher, text="Предупреждения:", style='Warning.TLabel').pack(anchor='w', padx=10)

        # Warnings display area (readonly)
        self.warnings_area = scrolledtext.ScrolledText(self.tab_cipher, height=6, state='disabled', foreground=COLORS['warning'])
        self.warnings_area.pack(fill='x', padx=10, pady=(0,10))

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
        top_frame.pack(side='top', fill='both', expand=True, pady=(0,5))

        ttk.Label(top_frame, text="Base64 код:", style='Input.TLabel').pack(anchor='w')
        self.base64_encode_input = scrolledtext.ScrolledText(top_frame, font=('Consolas', 12), height=15)
        self.base64_encode_input.pack(expand=True, fill='both')

        # Bottom frame for decoded output
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(side='top', fill='both', expand=True)

        ttk.Label(bottom_frame, text="Декодированный текст:", style='Output.TLabel').pack(anchor='w')
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
        top_frame.pack(side='top', fill='both', expand=True, pady=(0,5))

        ttk.Label(top_frame, text="Введите текст для SHA3-256:", style='Input.TLabel').pack(anchor='w')
        self.sha3_input = scrolledtext.ScrolledText(top_frame, font=('Consolas', 12), height=15)
        self.sha3_input.pack(expand=True, fill='both')

        # Bottom frame for output
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(side='top', fill='both', expand=True)

        ttk.Label(bottom_frame, text="Хеш SHA3-256:", style='Output.TLabel').pack(anchor='w')
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
        top_frame.pack(side='top', fill='both', expand=True, pady=(0,5))

        ttk.Label(top_frame, text="Введите текст для BLAKE2b:", style='Input.TLabel').pack(anchor='w')
        self.blake2b_input = scrolledtext.ScrolledText(top_frame, font=('Consolas', 12), height=15)
        self.blake2b_input.pack(expand=True, fill='both')

        # Bottom frame for output
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(side='top', fill='both', expand=True)

        ttk.Label(bottom_frame, text="Хеш BLAKE2b:", style='Output.TLabel').pack(anchor='w')
        self.blake2b_output = scrolledtext.ScrolledText(bottom_frame, font=('Consolas', 12), height=15, state='disabled')
        self.blake2b_output.pack(expand=True, fill='both')

        # Bind text change event to update hash
        self.blake2b_input.bind('<KeyRelease>', self.on_blake2b_input_change)

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

if __name__ == "__main__":
    app = CipherApp()
    app.mainloop()