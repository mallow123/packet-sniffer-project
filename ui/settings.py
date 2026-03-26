from database import save_setting, load_settings


def save_preferences(app):
    save_setting("alert_threshold", app.threshold_var.get().strip())
    save_setting("suspicious_ports", app.ports_var.get().strip())
    save_setting("auto_save_packets", str(app.autosave_var.get()))
    save_setting("theme_mode", app.theme_var.get())
    save_setting("show_toasts", str(app.toast_var.get()))
    save_setting("default_interface", app.interface_var.get())

    app.settings = load_settings()
    app.show_toast("Settings Saved", "Your preferences have been updated.", app.GREEN)
