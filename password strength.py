import tkinter as tk
from tkinter import ttk, messagebox
import string
import random

COMMON_PASSWORDS = ["123456", "password", "123456789", "qwerty", "12345678", "111111", "123123"]

def assess_password_strength(password):
    length_score = len(password) >= 8
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    unique_chars = len(set(password)) > 5
    not_common = password not in COMMON_PASSWORDS

    score = sum([length_score, has_upper, has_lower, has_digit, has_special, unique_chars, not_common])
    strength = "Weak"
    color = "#FF3B3B"  # Red
    if score <= 2:
        strength = "Very Weak"
    elif score == 3:
        strength = "Weak"
    elif score == 4:
        strength = "Moderate"
        color = "#FFA500"  # Orange
    elif score == 5:
        strength = "Strong"
        color = "#FFD700"  # Yellow
    elif score >= 6:
        strength = "Very Strong"
        color = "#00FF7F"  # Green

    return strength, color, score, {
        "Length (>=8)": length_score,
        "Uppercase": has_upper,
        "Lowercase": has_lower,
        "Digit": has_digit,
        "Special Character": has_special,
        "Unique Characters (>5)": unique_chars,
        "Not a Common Password": not_common,
    }

def analyze_password():
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password.")
        return

    strength, color, score, details = assess_password_strength(password)
    result_label.config(text=f"Password Strength: {strength}", fg=color)

    progress_bar["value"] = (score / 7) * 100

    suggestions = []
    if not details["Length (>=8)"]:
        suggestions.append("Increase password length to at least 8 characters.")
    if not details["Uppercase"]:
        suggestions.append("Add at least one uppercase letter.")
    if not details["Lowercase"]:
        suggestions.append("Add at least one lowercase letter.")
    if not details["Digit"]:
        suggestions.append("Include at least one numeric digit.")
    if not details["Special Character"]:
        suggestions.append("Add at least one special character (e.g., @, #, $).")
    if not details["Unique Characters (>5)"]:
        suggestions.append("Use a more diverse set of characters.")
    if not details["Not a Common Password"]:
        suggestions.append("Avoid common passwords.")

    # Update result box with details and suggestions
    result_text.config(state="normal")
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, "Details:\n")
    result_text.insert(tk.END, "\n".join([f"{key}: {'✔' if value else '✘'}" for key, value in details.items()]) + "\n\n")
    result_text.insert(tk.END, "Suggestions:\n")
    result_text.insert(tk.END, "\n".join(suggestions) if suggestions else "Your password is strong!")
    result_text.config(state="disabled")

def toggle_password():
    if show_password_var.get():
        password_entry.config(show="")
    else:
        password_entry.config(show="*")

def reset_fields():
    password_entry.delete(0, tk.END)
    result_label.config(text="")
    progress_bar["value"] = 0
    result_text.config(state="normal")
    result_text.delete("1.0", tk.END)
    result_text.config(state="disabled")
    show_password_var.set(False)
    password_entry.config(show="*")

def generate_password():
    length = 12
    characters = string.ascii_letters + string.digits + string.punctuation
    password = "".join(random.choice(characters) for _ in range(length))
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)

root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("600x500")
root.configure(bg="#1E1E1E")  # Dark background

# Title
title_label = tk.Label(root, text="Password Strength Checker", font=("Segoe UI", 20,"bold"), fg="#FFFFFF", bg="#1E1E1E")
title_label.pack(pady=10)

# Password Input Frame
password_frame = tk.Frame(root, bg="#1E1E1E")
password_frame.pack(pady=10)

password_label = tk.Label(password_frame, text="Enter Password:", font=("Segoe UI", 14), fg="#CCCCCC", bg="#1E1E1E")
password_label.grid(row=0, column=0, padx=5)

password_entry = tk.Entry(password_frame, font=("Segoe UI", 14), show="*", width=30, bg="#2E2E2E", fg="#FFFFFF", insertbackground="#FFFFFF", relief="flat")
password_entry.grid(row=0, column=1, padx=5)

show_password_var = tk.BooleanVar()
show_password_checkbox = tk.Checkbutton(password_frame, text="Show Password", font=("Segoe UI", 12), bg="#1E1E1E", fg="#CCCCCC",
                                        activebackground="#1E1E1E", activeforeground="#CCCCCC", selectcolor="#1E1E1E", 
                                        variable=show_password_var, command=toggle_password)
show_password_checkbox.grid(row=1, columnspan=2, pady=5)

# Buttons
button_frame = tk.Frame(root, bg="#1E1E1E")
button_frame.pack(pady=10)

analyze_button = tk.Button(button_frame, text="Analyze", font=("Segoe UI", 14), bg="#1E90FF", fg="#FFFFFF", command=analyze_password, relief="flat", width=12)
analyze_button.grid(row=0, column=0, padx=5)

reset_button = tk.Button(button_frame, text="Reset", font=("Segoe UI", 14), bg="#1E90FF", fg="#FFFFFF", command=reset_fields, relief="flat", width=12)
reset_button.grid(row=0, column=1, padx=5)

generate_button = tk.Button(button_frame, text="Generate Password", font=("Segoe UI", 14), bg="#1E90FF", fg="#FFFFFF", command=generate_password, relief="flat", width=18)
generate_button.grid(row=0, column=2, padx=5)

# Progress Bar
progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate", style="custom.Horizontal.TProgressbar")
progress_bar.pack(pady=10)

result_label = tk.Label(root, text="", font=("Segoe UI", 16), fg="#FFFFFF", bg="#1E1E1E")
result_label.pack(pady=10)

# Result Box with Scrollbar
result_frame = tk.Frame(root, bg="#1E1E1E")
result_frame.pack(pady=10)

result_border = tk.Frame(result_frame, bg="#FFFFFF", width=400, height=200, highlightbackground="#2E2E2E", highlightthickness=1)
result_border.pack(pady=5)

result_text = tk.Text(result_border, font=("Segoe UI", 12), wrap="word", height=55, width=60, bg="#2E2E2E", fg="#FFFFFF", insertbackground="#FFFFFF", relief="flat", state="disabled")
result_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)

scrollbar = ttk.Scrollbar(result_border, orient="vertical", command=result_text.yview)
scrollbar.pack(side="right", fill="y")

result_text.configure(yscrollcommand=scrollbar.set)

# Style Configuration
style = ttk.Style()
style.configure("custom.Horizontal.TProgressbar", troughcolor="#2E2E2E", bordercolor="#2E2E2E", background="#1E90FF", lightcolor="#1E90FF", darkcolor="#1E90FF")

root.mainloop()
