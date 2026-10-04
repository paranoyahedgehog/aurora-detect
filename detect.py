import os
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Сигнатуры для поиска
EXACT_SIGNATURES = [
    b"89.126.248.81",
    b"4a7f21de09bc44115c3af0882d6eb347",
    b"ldr.png",
    b"/assets/ldr.png"
]

GENERIC_SUSPICIOUS = [
    b"VirtualAllocEx",
    b"WriteProcessMemory",
    b"CreateRemoteThread",
    b"LoadLibraryA",
    b"GetProcAddress"
]

TARGET_EXTENSIONS = ('.py', '.pyw', '.txt')


class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Cheat & Injector Detector")
        self.root.geometry("720x520")
        self.root.resizable(False, False)

        # UI Стили
        self.root.configure(bg="#1e1e2e")
        style = ttk.Style()
        style.theme_use('clam')

        # Заголовок
        header = tk.Label(
            root, text="Поиск Python-инжектора и лоадера", 
            font=("Arial", 14, "bold"), fg="#cdd6f4", bg="#1e1e2e"
        )
        header.pack(pady=10)

        # Кнопки управления
        btn_frame = tk.Frame(root, bg="#1e1e2e")
        btn_frame.pack(pady=5)

        self.btn_fast = tk.Button(
            btn_frame, text="🚀 Быстрое сканирование (User/Temp)", 
            command=self.start_fast_scan, bg="#a6e3a1", fg="#11111b", 
            font=("Arial", 10, "bold"), padx=10, pady=5
        )
        self.btn_fast.grid(row=0, column=0, padx=5)

        self.btn_full = tk.Button(
            btn_frame, text="💾 Диск C:", 
            command=self.start_c_scan, bg="#89b4fa", fg="#11111b", 
            font=("Arial", 10, "bold"), padx=10, pady=5
        )
        self.btn_full.grid(row=0, column=1, padx=5)

        self.btn_custom = tk.Button(
            btn_frame, text="📁 Выбрать папку", 
            command=self.start_custom_scan, bg="#fab387", fg="#11111b", 
            font=("Arial", 10, "bold"), padx=10, pady=5
        )
        self.btn_custom.grid(row=0, column=2, padx=5)

        # Статус
        self.status_lbl = tk.Label(
            root, text="Готов к проверке", 
            fg="#bac2de", bg="#1e1e2e", font=("Arial", 9)
        )
        self.status_lbl.pack(pady=5)

        # Текстовое окно для логов
        self.log_text = tk.Text(
            root, bg="#181825", fg="#cdd6f4", 
            font=("Consolas", 9), height=18, width=85, relief="flat"
        )
        self.log_text.pack(padx=15, pady=5)

        # Теги для подсветки
        self.log_text.tag_config("DANGER", foreground="#f38ba8", font=("Consolas", 9, "bold"))
        self.log_text.tag_config("WARN", foreground="#f9e2af", font=("Consolas", 9, "bold"))
        self.log_text.tag_config("OK", foreground="#a6e3a1")

        self.is_scanning = False

    def log(self, text, tag=None):
        self.log_text.insert(tk.END, text + "\n", tag)
        self.log_text.see(tk.END)

    def set_buttons_state(self, state):
        self.btn_fast.config(state=state)
        self.btn_full.config(state=state)
        self.btn_custom.config(state=state)

    def check_file(self, filepath):
        try:
            # Пропускаем огромные файлы > 10MB
            if os.path.getsize(filepath) > 10 * 1024 * 1024:
                return

            with open(filepath, 'rb') as f:
                content = f.read()

            # 1. Проверка на точное совпадение с этим читом
            for sig in EXACT_SIGNATURES:
                if sig in content:
                    self.log(f"[!!! НАЙДЕН ЧИТ ИЗ ЗАПРОСА !!!] -> {filepath}", "DANGER")
                    self.log(f"   └─ Содержит сигнатуру: {sig.decode('utf-8', errors='ignore')}", "DANGER")
                    return

            # 2. Проверка на универсальный PE-инжектор в Python
            matched_apis = [api for api in GENERIC_SUSPICIOUS if api in content]
            if len(matched_apis) >= 3:
                self.log(f"[ПОДОЗРИТЕЛЬНЫЙ ИНЖЕКТОР] -> {filepath}", "WARN")
                found_apis = b", ".join(matched_apis).decode('utf-8', errors='ignore')
                self.log(f"   └─ Вызовы памяти: {found_apis}", "WARN")

        except (PermissionError, FileNotFoundError):
            pass
        except Exception as e:
            pass

    def scan_directories(self, paths):
        self.is_scanning = True
        self.set_buttons_state(tk.DISABLED)
        self.log(f"--- НАЧАЛО ПРОВЕРКИ ---")

        total_checked = 0
        for base_path in paths:
            if not os.path.exists(base_path):
                continue
            self.status_lbl.config(text=f"Сканирование: {base_path}...")
            for root_dir, _, files in os.walk(base_path):
                for file in files:
                    if file.lower().endswith(TARGET_EXTENSIONS):
                        full_path = os.path.join(root_dir, file)
                        self.check_file(full_path)
                        total_checked += 1

        self.log(f"--- ПРОВЕРКА ЗАВЕРШЕНА (Проверено файлов: {total_checked}) ---", "OK")
        self.status_lbl.config(text="Проверка окончена!")
        self.is_scanning = False
        self.set_buttons_state(tk.NORMAL)

    def start_fast_scan(self):
        user_profile = os.environ.get('USERPROFILE', '')
        local_app_data = os.environ.get('LOCALAPPDATA', '')
        app_data = os.environ.get('APPDATA', '')
        temp = os.environ.get('TEMP', '')

        paths_to_scan = [
            os.path.join(user_profile, 'Desktop'),
            os.path.join(user_profile, 'Downloads'),
            os.path.join(user_profile, 'Documents'),
            temp,
            os.path.join(local_app_data, 'Programs'),
            os.path.join(app_data)
        ]
        threading.Thread(target=self.scan_directories, args=(paths_to_scan,), daemon=True).start()

    def start_c_scan(self):
        if messagebox.askyesno("Внимание", "Сканирование всего диска C: может занять 1-3 минуты. Продолжить?"):
            threading.Thread(target=self.scan_directories, args=(["C:\\"],), daemon=True).start()

    def start_custom_scan(self):
        folder = filedialog.askdirectory()
        if folder:
            threading.Thread(target=self.scan_directories, args=([folder],), daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerApp(root)
    root.mainloop()
