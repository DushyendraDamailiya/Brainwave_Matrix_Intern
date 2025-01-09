import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter.ttk import Progressbar
import re
import requests
from urllib.parse import urlparse
from fpdf import FPDF

# Check if a URL is suspicious based on patterns that are common in phishing attempts
def is_suspicious_url(url):
    suspicious_patterns = {
        r"login|signin|update|verify|account": "Contains suspicious keywords (e.g., login, signin, verify, etc.)",
        r"[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}": "Contains an IP address instead of a domain name",
        r"-": "Contains hyphens in the domain name (often used in fake URLs)",
    }
    detected_patterns = []
    for pattern, description in suspicious_patterns.items():
        if re.search(pattern, url):
            detected_patterns.append(description)
    return detected_patterns

# Check if a URL exists in a predefined blacklist
def check_blacklist(url):
    blacklist = [
        "examplephishingsite.com",
        "malicious-site.net",
        "fakebank-login.com",
    ]
    domain = urlparse(url).netloc
    return domain in blacklist

# Expand shortened URLs to their full version
def expand_url(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url
    except Exception:
        return url  # If expansion fails, return the original URL

# Function to handle the scanning process
def scan_url():
    url = url_entry.get().strip()
    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL to scan.")
        return

    try:
        # Expand the URL if it's shortened
        expanded_url = expand_url(url)

        # Clear previous results
        result_box.delete(1.0, tk.END)
        result_box.insert(tk.END, f"Scanning URL: {expanded_url}\n\n")

        # Check for suspicious patterns
        detected_patterns = is_suspicious_url(expanded_url)
        if detected_patterns:
            result_box.insert(tk.END, "Warning: The URL contains suspicious patterns:\n")
            for pattern in detected_patterns:
                result_box.insert(tk.END, f"- {pattern}\n")
        else:
            result_box.insert(tk.END, "No suspicious patterns detected.\n")

        # Check if the URL is in the blacklist
        if check_blacklist(expanded_url):
            result_box.insert(tk.END, "\nAlert: The URL is blacklisted!\n")
        else:
            result_box.insert(tk.END, "\nThe URL is not blacklisted and appears safe.\n")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Save the scan results to a PDF file
def save_results():
    file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
    if file_path:
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Times", size=12)
            pdf.multi_cell(0, 10, result_box.get(1.0, tk.END))
            pdf.output(file_path)
            messagebox.showinfo("Success", "Results saved successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save results: {e}")

# Reset the input and result fields
def reset():
    url_entry.delete(0, tk.END)
    result_box.delete(1.0, tk.END)

# Build the GUI interface
def create_gui():
    root = tk.Tk()
    root.title("Phishing Link Scanner")
    root.configure(bg="#4682B4")  # Steel blue background

    # Header section
    tk.Label(root, text="Phishing Link Scanner", font=("Times New Roman", 18, "bold"), bg="#4682B4", fg="white").pack(pady=10)

    # Input field for URL
    tk.Label(root, text="Enter the URL to scan:", font=("Times New Roman", 12), bg="#4682B4", fg="white").pack(pady=5)
    global url_entry
    url_entry = tk.Entry(root, width=50, font=("Times New Roman", 12))
    url_entry.pack(pady=5)

    # Buttons section
    button_frame = tk.Frame(root, bg="#4682B4")
    button_frame.pack(pady=10)

    scan_button = tk.Button(button_frame, text="Scan URL", command=scan_url, font=("Times New Roman", 12), bg="white", fg="black")
    scan_button.grid(row=0, column=0, padx=5)

    save_button = tk.Button(button_frame, text="Save Results", command=save_results, font=("Times New Roman", 12), bg="white", fg="black")
    save_button.grid(row=0, column=1, padx=5)

    reset_button = tk.Button(button_frame, text="Reset", command=reset, font=("Times New Roman", 12), bg="white", fg="black")
    reset_button.grid(row=0, column=2, padx=5)

    # Results section with a scrollbar
    tk.Label(root, text="Scan Results:", font=("Times New Roman", 12, "bold"), bg="#4682B4", fg="white").pack(pady=5)
    result_frame = tk.Frame(root, bg="#4682B4")
    result_frame.pack(pady=5)

    scrollbar = tk.Scrollbar(result_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    global result_box
    result_box = tk.Text(result_frame, width=60, height=10, font=("Times New Roman", 12), wrap=tk.WORD, yscrollcommand=scrollbar.set)
    result_box.pack(side=tk.LEFT, fill=tk.BOTH)

    scrollbar.config(command=result_box.yview)

    # Placeholder for a progress bar (future feature)
    progress = Progressbar(root, orient=tk.HORIZONTAL, length=400, mode="determinate")
    progress.pack(pady=10)

    # Finalize the GUI window
    root.geometry("600x500")
    root.mainloop()

# Entry point of the application
if __name__ == "__main__":
    create_gui()
