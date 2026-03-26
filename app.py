from database import init_db, load_alerts
from models import AppState
from ui.login import show_login

def launch_dashboard():
    from ui.dashboard import launch_dashboard_ui
    state = AppState()
    state.alerts_data = load_alerts()
    launch_dashboard_ui(state)

if __name__ == "__main__":
    init_db()
    show_login(launch_dashboard)
