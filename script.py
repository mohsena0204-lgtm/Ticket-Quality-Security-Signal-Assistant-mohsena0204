"""
Ticket Quality + Security Signal Assistant

This Python script provides a graphical user interface (GUI) to process ticket notes, generate ticket classifications, assess security signals, and suggest next actions. Updated to use Tkinter for the GUI framework while adhering to local-only constraints with no external dependencies.

Requirements:
    - Python 3.7+
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext


def classify_ticket(notes):
    """
    Classify the ticket into a category based on keywords.
    """
    keywords = {
        "VPN": ["vpn", "network issue", "vpn connection"],
        "Slow Performance": ["slow", "performance issue", "lag", "bottleneck"],
        "Password Reset": ["password reset", "forgot password", "locked out"],
        "Application Issue": ["application", "app issue", "software crash"],
        "MacBook Issue": ["macbook", "mac os", "mac freezes", "apple"],
    }
    for category, key_list in keywords.items():
        for keyword in key_list:
            if keyword.lower() in notes.lower():
                return category
    return "General"


def analyze_security_signal(notes):
    """
    Assess security signal levels based on keywords.
    """
    escalate_keywords = [
        "unexpected mfa", "suspicious login", "hacked", "phishing",
        "clicked link and entered password", "mailbox forwarding rule",
        "malware", "ransomware", "unknown remote access tool", "teamviewer", "anydesk"
    ]
    caution_keywords = [
        "vpn issue after password reset", "repeated lockouts", "new device access issue"
    ]
    notes_lower = notes.lower()

    if any(kw in notes_lower for kw in escalate_keywords):
        return "Escalate", "Keywords: " + ", ".join(kw for kw in escalate_keywords if kw in notes_lower)
    if any(kw in notes_lower for kw in caution_keywords):
        return "Caution", "Keywords: " + ", ".join(kw for kw in caution_keywords if kw in notes_lower)
    return "Normal", "No security concerns detected."


def suggest_next_actions(category):
    """
    Provide suggested next actions based on the ticket category.
    """
    suggestions = {
        "VPN": "Verify VPN credentials, restart VPN client, check network connectivity.",
        "Slow Performance": "Close unused applications, verify system resources, restart the device.",
        "Password Reset": "Guide user through password reset steps, verify identity, check for lockouts.",
        "Application Issue": "Reinstall/repair the application, check logs, verify compatibility.",
        "MacBook Issue": "Reset NVRAM/PRAM, validate OS updates, test hardware diagnostics.",
        "General": "Gather more details, check recent history, and escalate if needed."
    }
    return suggestions.get(category, "No specific actions available.")


def process_ticket_notes():
    """
    Process the ticket notes entered by the user and display results.
    """
    notes = ticket_notes_text.get("1.0", "end").strip()
    if not notes:
        messagebox.showerror("Error", "Please enter ticket notes.")
        return

    # Classify the ticket
    category = classify_ticket(notes)

    # Analyze the security signal
    security_level, reasons = analyze_security_signal(notes)

    # Get suggested actions
    suggestions = suggest_next_actions(category)

    # Display results
    results_text.delete("1.0", "end")
    results_text.insert("end", f"Category: {category}\n")
    results_text.insert("end", f"Security Level: {security_level}\n")
    results_text.insert("end", f"Security Reasons: {reasons}\n")
    results_text.insert("end", f"Suggested Actions: {suggestions}\n")


def clear_inputs():
    """
    Clear the input and output fields.
    """
    ticket_notes_text.delete("1.0", "end")
    results_text.delete("1.0", "end")


# Create the main application window
app = tk.Tk()
app.title("Ticket Quality + Security Signal Assistant")
app.geometry("600x600")

# Input label and text area
input_label = tk.Label(app, text="Paste Ticket Notes Below:")
input_label.pack(pady=5)

ticket_notes_text = scrolledtext.ScrolledText(app, wrap=tk.WORD, height=10, width=70)
ticket_notes_text.pack(padx=10, pady=5)

# Process and Clear buttons
button_frame = tk.Frame(app)
button_frame.pack(pady=10)

process_button = tk.Button(button_frame, text="Process Ticket", command=process_ticket_notes)
process_button.pack(side=tk.LEFT, padx=5)

clear_button = tk.Button(button_frame, text="Clear", command=clear_inputs)
clear_button.pack(side=tk.LEFT, padx=5)

# Results label and text area
results_label = tk.Label(app, text="Results:")
results_label.pack(pady=5)

results_text = scrolledtext.ScrolledText(app, wrap=tk.WORD, height=15, width=70, state=tk.NORMAL)
results_text.pack(padx=10, pady=5)

# Start the Tkinter event loop
app.mainloop()