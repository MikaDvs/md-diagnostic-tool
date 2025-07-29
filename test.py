import tkinter as tk
import tkinter.font as tkfont


def get_text_width():
    text_area.update_idletasks()  # Ensure geometry is updated
    width = text_area.winfo_width()
    font = tkfont.Font(font=text_area["font"])
    char_width = font.measure("=")

    if char_width == 0:
        # fallback
        return "=" * 50

    num = width // char_width

    # Subtract 1 or 2 as buffer to prevent wrapping
    if num > 2:
        num -= 2

    return "=" * num


def display_separator():
    text_area.delete(1.0, tk.END)
    text_area.insert(tk.END, get_text_width())


root = tk.Tk()
root.geometry("700x200")

text_area = tk.Text(root, font=("Courier New", 12))
text_area.pack(fill="both", expand=True)

root.after(200, display_separator)  # wait longer to ensure rendering
root.mainloop()
