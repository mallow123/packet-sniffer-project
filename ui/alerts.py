import tkinter as tk


def refresh_alerts_table(app):
    for item in app.alerts_table.get_children():
        app.alerts_table.delete(item)

    for alert in app.state.alerts_data:
        app.alerts_table.insert(
            "",
            tk.END,
            values=(
                alert["time"],
                alert["ip"],
                alert["port"],
                alert["type"],
                alert["severity"],
                alert["status"],
            ),
        )
