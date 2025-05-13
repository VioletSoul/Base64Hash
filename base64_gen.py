import base64
import hashlib
import codecs
import tkinter as tk
from tkinter import scrolledtext

# Define color scheme for different text parts in the output area
COLORS = {
    'header': '#DAA520',   # Golden color for headers and separators
    'label': '#1E90FF',    # Dodger blue for labels (algorithm names)
    'result': '#D3D3D3',   # Light gray for the encoded/hash results
    'input_label': '#228B22',  # Forest green for input label
}

# Function to encode string to Base64
def encode_base64(s):
    return base64.b64encode(s.encode('utf-8')).decode()

# Function to encode string to URL-safe Base64
def encode_base64_urlsafe(s):
    return base64.urlsafe_b64encode(s.encode('utf-8')).decode()

# Function to encode string to Base32
def encode_base32(s):
    return base64.b32encode(s.encode('utf-8')).decode()

# Function to encode string to hexadecimal representation
def encode_hex(s):
    return s.encode('utf-8').hex()

# Function to encode string using ROT13 cipher
def encode_rot13(s):
    return codecs.encode(s, 'rot_13')

# Function to calculate MD5 hash of the string
def encode_md5(s):
    return hashlib.md5(s.encode('utf-8')).hexdigest()

# Function to calculate SHA1 hash of the string
def encode_sha1(s):
    return hashlib.sha1(s.encode('utf-8')).hexdigest()

# Function to calculate SHA256 hash of the string
def encode_sha256(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

# Function to apply Caesar cipher with a fixed shift (default +3)
def caesar_cipher(text, shift=3):
    result = []
    # English uppercase letters
    eng_upper = [chr(c) for c in range(ord('A'), ord('Z')+1)]
    # English lowercase letters
    eng_lower = [chr(c) for c in range(ord('a'), ord('z')+1)]
    # Russian uppercase letters (Cyrillic)
    rus_upper = [chr(c) for c in range(ord('А'), ord('Я')+1)]
    # Russian lowercase letters (Cyrillic)
    rus_lower = [chr(c) for c in range(ord('а'), ord('я')+1)]

    for char in text:
        if char in eng_upper:
            idx = eng_upper.index(char)
            result.append(eng_upper[(idx + shift) % 26])
        elif char in eng_lower:
            idx = eng_lower.index(char)
            result.append(eng_lower[(idx + shift) % 26])
        elif char in rus_upper:
            idx = rus_upper.index(char)
            result.append(rus_upper[(idx + shift) % 32])
        elif char in rus_lower:
            idx = rus_lower.index(char)
            result.append(rus_lower[(idx + shift) % 32])
        else:
            # Non-alphabetic characters are unchanged
            result.append(char)
    return ''.join(result)

# Function to apply Atbash cipher (reverses alphabet)
def atbash_cipher(text):
    result = []
    eng_upper = [chr(c) for c in range(ord('A'), ord('Z')+1)]
    eng_lower = [chr(c) for c in range(ord('a'), ord('z')+1)]
    rus_upper = [chr(c) for c in range(ord('А'), ord('Я')+1)]
    rus_lower = [chr(c) for c in range(ord('а'), ord('я')+1)]

    for char in text:
        if char in eng_upper:
            idx = eng_upper.index(char)
            result.append(eng_upper[25 - idx])
        elif char in eng_lower:
            idx = eng_lower.index(char)
            result.append(eng_lower[25 - idx])
        elif char in rus_upper:
            idx = rus_upper.index(char)
            result.append(rus_upper[31 - idx])
        elif char in rus_lower:
            idx = rus_lower.index(char)
            result.append(rus_lower[31 - idx])
        else:
            # Non-alphabetic characters unchanged
            result.append(char)
    return ''.join(result)

# Function to apply XOR cipher with a fixed key (42)
def xor_cipher(s, key=42):
    # XOR each byte with key and return hex string
    xored = bytes([b ^ key for b in s.encode('utf-8')])
    return xored.hex()

# Main application class inheriting from Tkinter's Tk
class CipherApp(tk.Tk):
    def __init__(self):
        super().__init__()
        # Set window title and size
        self.title("Interactive Encoding and Hashing")
        self.geometry("900x650")

        # Label prompting user to enter text
        self.label_input = tk.Label(
            self,
            text="Enter text:",
            fg=COLORS['input_label'],
            font=("Consolas", 14, "bold")
        )
        self.label_input.pack(anchor='w', padx=10, pady=(10, 0))

        # Single-line text entry widget for user input
        self.entry_text = tk.Entry(self, font=("Consolas", 14))
        self.entry_text.pack(fill='x', padx=10, pady=(0, 10))
        self.entry_text.focus_set()  # Focus cursor here on start

        # Scrollable text widget to display encoding results
        self.output_area = scrolledtext.ScrolledText(
            self,
            font=("Consolas", 12),
            state='disabled',  # Read-only
            height=30
        )
        self.output_area.pack(fill='both', expand=True, padx=10, pady=10)

        # Bind key release event to update output dynamically
        self.entry_text.bind('<KeyRelease>', self.on_text_change)

        # Initialize output area with empty content
        self.update_output("")

    # Event handler called when user types or modifies input text
    def on_text_change(self, event=None):
        text = self.entry_text.get()
        self.update_output(text)

    # Updates the output area with encoded and hashed results
    def update_output(self, text):
        # Prepare lines to display: tuples with (text, tag) or (label, tag, result)
        lines = [
            ("----- ENCODING OUTPUT -----", 'header'),
            (f"Base64:          ", 'label', encode_base64(text)),
            (f"Base64 URL-safe: ", 'label', encode_base64_urlsafe(text)),
            (f"Base32:          ", 'label', encode_base32(text)),
            (f"Hex:             ", 'label', encode_hex(text)),
            (f"ROT13:           ", 'label', encode_rot13(text)),
            (f"Caesar (+3):     ", 'label', caesar_cipher(text)),
            (f"Atbash:          ", 'label', atbash_cipher(text)),
            (f"XOR (key=42):    ", 'label', xor_cipher(text)),
            (f"MD5:             ", 'label', encode_md5(text)),
            (f"SHA1:            ", 'label', encode_sha1(text)),
            (f"SHA256:          ", 'label', encode_sha256(text)),
            ("-----------------------------", 'header'),
            ("Current input: ", 'input_label', text)
        ]

        # Enable editing to update text widget
        self.output_area.config(state='normal')
        self.output_area.delete('1.0', tk.END)  # Clear previous content

        # Insert each line with appropriate tags for color and font
        for line in lines:
            if len(line) == 2:
                # Header or separator line
                self.output_area.insert(tk.END, line[0] + "\n", line[1])
            else:
                label, tag, result = line
                self.output_area.insert(tk.END, label, tag)
                self.output_area.insert(tk.END, result + "\n", 'result')

        # Disable editing to make output read-only
        self.output_area.config(state='disabled')

    # Configure tags with colors and fonts for the output area
    def setup_tags(self):
        self.output_area.tag_config('header', foreground=COLORS['header'], font=("Consolas", 13, "bold"))
        self.output_area.tag_config('label', foreground=COLORS['label'], font=("Consolas", 12, "bold"))
        self.output_area.tag_config('result', foreground=COLORS['result'], font=("Consolas", 12))
        self.output_area.tag_config('input_label', foreground=COLORS['input_label'], font=("Consolas", 12, "bold"))

# Entry point: create and run the application
if __name__ == "__main__":
    app = CipherApp()
    app.setup_tags()  # Setup text tags for coloring
    app.mainloop()    # Start Tkinter event loop
