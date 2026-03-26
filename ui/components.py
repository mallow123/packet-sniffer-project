import tkinter as tk


def make_button(parent, text, command, bg, fg="white", width=12):
    return tk.Button(
        parent,
        text=text,
        command=command,
        bg=bg,
        fg=fg,
        activebackground=bg,
        activeforeground=fg,
        relief="flat",
        bd=0,
        font=("Segoe UI", 10, "bold"),
        width=width,
        pady=8,
        cursor="hand2",
    )


def make_card(parent, bg, border="#222b36"):
    return tk.Frame(parent, bg=bg, highlightthickness=1, highlightbackground=border)


def make_title(parent, text, subtitle, bg, fg, muted):
    wrap = tk.Frame(parent, bg=bg)
    wrap.pack(side="left")

    tk.Label(
        wrap,
        text=text,
        bg=bg,
        fg=fg,
        font=("Segoe UI", 20, "bold")
    ).pack(anchor="w")

    tk.Label(
        wrap,
        text=subtitle,
        bg=bg,
        fg=muted,
        font=("Segoe UI", 10)
    ).pack(anchor="w", pady=(2, 0))


def make_stat_card(parent, title, value_color, card_bg, muted):
    card = make_card(parent, card_bg)
    card.pack(side="left", fill="x", expand=True, padx=6)

    tk.Label(
        card,
        text=title,
        bg=card_bg,
        fg=muted,
        font=("Segoe UI", 10, "bold")
    ).pack(anchor="w", padx=14, pady=(12, 4))

    value = tk.Label(
        card,
        text="0",
        bg=card_bg,
        fg=value_color,
        font=("Segoe UI", 18, "bold")
    )
    value.pack(anchor="w", padx=14, pady=(0, 12))
    return value


def make_info_card(parent, title, initial_value, value_color, card_bg, muted):
    card = make_card(parent, card_bg)
    card.pack(side="left", fill="x", expand=True, padx=6)

    tk.Label(
        card,
        text=title,
        bg=card_bg,
        fg=muted,
        font=("Segoe UI", 10, "bold")
    ).pack(anchor="w", padx=14, pady=(12, 4))

    value = tk.Label(
        card,
        text=initial_value,
        bg=card_bg,
        fg=value_color,
        font=("Segoe UI", 15, "bold")
    )
    value.pack(anchor="w", padx=14, pady=(0, 12))
    return value
