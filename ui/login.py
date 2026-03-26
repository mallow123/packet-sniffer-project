import tkinter as tk
from config import APP_BG, CARD_BG, ACCENT, MUTED, TABLE_BG, TEXT, GREEN
from database import authenticate_user

def show_login(on_success):
    login_window = tk.Tk()
    login_window.title("Secure Login")
    login_window.geometry("420x300")
    login_window.configure(bg=APP_BG)
    login_window.resizable(False, False)
    login_window.eval("tk::PlaceWindow . center")

    login_card = tk.Frame(login_window, bg=CARD_BG, highlightthickness=1, highlightbackground="#222b36")
    login_card.pack(fill="both", expand=True, padx=18, pady=18)

    tk.Label(login_card, text="Packet Analyzer Login", fg=ACCENT, bg=CARD_BG, font=("Segoe UI", 17, "bold")).pack(pady=(22, 6))
    tk.Label(login_card, text="Sign in to access the security monitoring dashboard", fg=MUTED, bg=CARD_BG, font=("Segoe UI", 10)).pack(pady=(0, 14))

    user_wrap = tk.Frame(login_card, bg=CARD_BG)
    user_wrap.pack(fill="x", padx=28, pady=(0, 10))
    tk.Label(user_wrap, text="Username", fg=ACCENT, bg=CARD_BG, font=("Segoe UI", 10, "bold")).pack(anchor="w")
    username_entry = tk.Entry(user_wrap, bg=TABLE_BG, fg=TEXT, insertbackground="white", relief="flat", font=("Segoe UI", 11), width=26)
    username_entry.pack(fill="x", ipady=6, pady=(6, 0))

    pass_wrap = tk.Frame(login_card, bg=CARD_BG)
    pass_wrap.pack(fill="x", padx=28, pady=(0, 10))
    tk.Label(pass_wrap, text="Password", fg=ACCENT, bg=CARD_BG, font=("Segoe UI", 10, "bold")).pack(anchor="w")
    password_entry = tk.Entry(pass_wrap, show="*", bg=TABLE_BG, fg=TEXT, insertbackground="white", relief="flat", font=("Segoe UI", 11), width=26)
    password_entry.pack(fill="x", ipady=6, pady=(6, 0))

    def do_login():
        if authenticate_user(username_entry.get().strip(), password_entry.get().strip()):
            login_window.destroy()
            on_success()
        else:
            from tkinter import messagebox
            messagebox.showerror("Login Failed", "Invalid credentials")

    tk.Button(
        login_card,
        text="Login",
        command=do_login,
        bg=GREEN,
        fg="white",
        relief="flat",
        bd=0,
        width=16,
        pady=8,
        font=("Segoe UI", 10, "bold"),
        cursor="hand2"
    ).pack(pady=18)

    password_entry.bind("<Return>", lambda event: do_login())
    username_entry.bind("<Return>", lambda event: password_entry.focus())

    login_window.mainloop()
