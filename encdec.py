import tkinter as tk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk


def binary_to_text(binary):
    binary_values = binary.split()
    ascii_string = ""
    for binary_value in binary_values:
        an_integer = int(binary_value, 2)
        ascii_character = chr(an_integer)
        ascii_string += ascii_character
    return ascii_string


def text_to_binary(text):
    binary_string = ' '.join(format(ord(char), '08b') for char in text)
    return binary_string


def rot13(text):
    result = ""
    for char in text:
        if char.isalpha():
            shift = 13
            if char.islower():
                shift += ord('a')
                result += chr(((ord(char) - ord('a') + 13) % 26) + ord('a'))
            else:
                result += chr(((ord(char) - ord('A') + 13) % 26) + ord('A'))
        else:
            result += char
    return result


def encrypt_hex(text):
    return ''.join(format(ord(char), '02x') for char in text)


def decrypt_hex(hex_string):
    bytes_object = bytes.fromhex(hex_string)
    return bytes_object.decode("ASCII")


def encrypt_decrypt_substitution(message):
    result = ""
    for char in message:
        if char.isalpha():
            if char.islower():
                result += chr(219 - ord(char))  # 'z' - char + 'a'
            else:
                result += chr(155 - ord(char))  # 'Z' - char + 'A'
        else:
            result += char
    return result


def handle_binary():
    def encrypt():
        input_text = input_textbox.get("1.0", tk.END).strip()
        result = text_to_binary(input_text)
        output_textbox.delete("1.0", tk.END)
        output_textbox.insert(tk.END, result)

    def decrypt():
        input_text = input_textbox.get("1.0", tk.END).strip()
        result = binary_to_text(input_text)
        output_textbox.delete("1.0", tk.END)
        output_textbox.insert(tk.END, result)

    input_label.config(text="Enter text or binary:")
    encrypt_button.config(command=encrypt)
    decrypt_button.config(command=decrypt)
    status_label.config(text="Binary Encryption/Decryption")


def handle_rot13():
    def process():
        input_text = input_textbox.get("1.0", tk.END).strip()
        result = rot13(input_text)
        output_textbox.delete("1.0", tk.END)
        output_textbox.insert(tk.END, result)

    input_label.config(text="Enter message:")
    encrypt_button.config(text="Encrypt/Decrypt", command=process)
    decrypt_button.pack_forget()
    status_label.config(text="ROT13 Encryption/Decryption")


def handle_hex():
    def encrypt():
        input_text = input_textbox.get("1.0", tk.END).strip()
        result = encrypt_hex(input_text)
        output_textbox.delete("1.0", tk.END)
        output_textbox.insert(tk.END, result)

    def decrypt():
        input_text = input_textbox.get("1.0", tk.END).strip()
        result = decrypt_hex(input_text)
        output_textbox.delete("1.0", tk.END)
        output_textbox.insert(tk.END, result)

    input_label.config(text="Enter text or hex:")
    encrypt_button.config(command=encrypt)
    decrypt_button.config(command=decrypt)
    decrypt_button.pack()
    status_label.config(text="Hex Encryption/Decryption")


def handle_substitution():
    def process():
        input_text = input_textbox.get("1.0", tk.END).strip()
        result = encrypt_decrypt_substitution(input_text)
        output_textbox.delete("1.0", tk.END)
        output_textbox.insert(tk.END, result)

    input_label.config(text="Enter message:")
    encrypt_button.config(text="Encrypt/Decrypt", command=process)
    decrypt_button.pack_forget()
    status_label.config(text="Substitution Cipher Encryption/Decryption")


def copy_output():
    root.clipboard_clear()
    root.clipboard_append(output_textbox.get("1.0", tk.END).strip())
    messagebox.showinfo("Copy to Clipboard", "Output copied to clipboard")


def clear_text():
    input_textbox.delete("1.0", tk.END)
    output_textbox.delete("1.0", tk.END)


# Setting up the main window
root = tk.Tk()
root.title("Encryption/Decryption")
root.geometry("600x500")
root.configure(bg="#2E2E2E")

style = ttk.Style()
style.theme_use("clam")

style.configure("TLabel", background="#2E2E2E", foreground="white", font=("Helvetica", 10))
style.configure("TButton", background="#4D4D4D", foreground="white", font=("Helvetica", 10))
style.configure("TFrame", background="#2E2E2E")
style.configure("TMenu", background="#2E2E2E", foreground="white", font=("Helvetica", 10))

# Menu bar
menu_bar = tk.Menu(root, bg="#2E2E2E", fg="white")
root.config(menu=menu_bar)

file_menu = tk.Menu(menu_bar, tearoff=0, bg="#2E2E2E", fg="white")
menu_bar.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="Clear", command=clear_text)
file_menu.add_command(label="Exit", command=root.quit)

edit_menu = tk.Menu(menu_bar, tearoff=0, bg="#2E2E2E", fg="white")
menu_bar.add_cascade(label="Edit", menu=edit_menu)
edit_menu.add_command(label="Copy Output", command=copy_output)

# Menu options frame
menu_frame = ttk.Frame(root)
menu_frame.pack(pady=10)

# Menu options
menu_label = ttk.Label(menu_frame, text="Encryption/Decryption", font=("Helvetica", 16, "bold"))
menu_label.pack(pady=5)

options = ["Binary", "ROT13", "HEX", "Substitution Ciphers", "Exit"]
handlers = [handle_binary, handle_rot13, handle_hex, handle_substitution, root.quit]

for option, handler in zip(options, handlers):
    button = ttk.Button(menu_frame, text=option, command=handler)
    button.pack(fill="x", pady=2)

# Input frame
input_frame = ttk.Frame(root)
input_frame.pack(pady=10)

input_label = ttk.Label(input_frame, text="Enter text:")
input_label.pack()

input_textbox = ScrolledText(input_frame, height=5, width=60, bg="#1E1E1E", fg="white", insertbackground="white")
input_textbox.pack()

# Output frame
output_frame = ttk.Frame(root)
output_frame.pack(pady=10)

output_label = ttk.Label(output_frame, text="Output:")
output_label.pack()

output_textbox = ScrolledText(output_frame, height=5, width=60, bg="#1E1E1E", fg="white", insertbackground="white")
output_textbox.pack()

# Button frame
button_frame = ttk.Frame(root)
button_frame.pack(pady=10)

encrypt_button = ttk.Button(button_frame, text="Encrypt")
encrypt_button.pack(side=tk.LEFT, padx=10)

decrypt_button = ttk.Button(button_frame, text="Decrypt")
decrypt_button.pack(side=tk.LEFT, padx=10)

# Status bar
status_label = ttk.Label(root, text="Welcome to Encryption/Decryption program", relief=tk.SUNKEN, anchor=tk.W)
status_label.pack(side=tk.BOTTOM, fill=tk.X)

# Start the GUI loop
root.mainloop()