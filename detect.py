import os
import sys
import subprocess
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
        self.root.title("Python Cheat Detector & Manager")
        self.root.geometry("850x620")
        self.root.resizable(False, False)
        self.root.configure(bg="#1e1e2e")

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", background="#181825", foreground="#cdd6f4", fieldbackground="#181825", font=("Consolas", 9))
        style.configure("Treeview.Heading", background="#313244", foreground="#cdd6f4", font=("Arial", 9, "bold"))
        style.map("Treeview", background=[('selected', '#45475a')], foreground=[('selected', '#f5e0dc')])

        # Заголовок
        header = tk.Label(
            root, text="Детектор и управление Python-читами", 
            font=("Arial", 14, "bold"), fg="#cdd6f4", bg="#1e1e2e"
        )
        header.pack(pady=8)

        # Панель запуска сканирования
        btn_frame = tk.Frame(root, bg="#1e1e2e")
        btn_frame.pack(pady=4)

        self.btn_fast = tk.Button(
            btn_frame, text="🚀 Быстрый скан (User/Temp)", 
            command=self.start_fast_scan, bg="#a6e3a1", fg="#11111b", 
            font=("Arial", 9, "bold"), padx=10, pady=4, relief="flat", cursor="hand2"
        )
        self.btn_fast.grid(row=0, column=0, padx=4)

        self.btn_full = tk.Button(
            btn_frame, text="💾 Диск C:", 
            command=self.start_c_scan, bg="#89b4fa", fg="#11111b", 
            font=("Arial", 9, "bold"), padx=10, pady=4, relief="flat", cursor="hand2"
        )
        self.btn_full.grid(row=0, column=1, padx=4)

        self.btn_custom = tk.Button(
            btn_frame, text="📁 Выбрать папку", 
            command=self.start_custom_scan, bg="#fab387", fg="#11111b", 
            font=("Arial", 9, "bold"), padx=10, pady=4, relief="flat", cursor="hand2"
        )
        self.btn_custom.grid(row=0, column=2, padx=4)

        # Таблица найденных читов
        tree_frame = tk.Frame(root, bg="#1e1e2e")
        tree_frame.pack(padx=15, pady=6, fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(tree_frame, columns=("threat", "path"), show="headings", height=8)
        self.tree.heading("threat", text="Угроза / Тип")
        self.tree.heading("path", text="Полный путь к файлу")
        self.tree.column("threat", width=180, anchor="center")
        self.tree.column("path", width=620, anchor="w")

        scroll_y = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll_y.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        # Панель действий с выбранным файлом
        action_frame = tk.Frame(root, bg="#1e1e2e")
        action_frame.pack(pady=6)

        self.btn_open = tk.Button(
            action_frame, text="📂 Открыть папку с файлом", 
            command=self.open_file_folder, bg="#f9e2af", fg="#11111b", 
            font=("Arial", 10, "bold"), padx=15, pady=5, relief="flat", cursor="hand2"
        )
        self.btn_open.grid(row=0, column=0, padx=10)

        self.btn_run = tk.Button(
            action_frame, text="▶️ Запустить файл", 
            command=self.run_selected_file, bg="#f38ba8", fg="#11111b", 
            font=("Arial", 10, "bold"), padx=15, pady=5, relief="flat", cursor="hand2"
        )
        self.btn_run.grid(row=0, column=1, padx=10)

        # Лог работы
        self.log_text = tk.Text(
            root, bg="#181825", fg="#cdd6f4", 
            font=("Consolas", 8), height=6, relief="flat"
        )
        self.log_text.pack(padx=15, pady=4, fill=tk.X)

        self.status_lbl = tk.Label(
            root, text="Готов к проверке", 
            fg="#bac2de", bg="#1e1e2e", font=("Arial", 8)
        )
        self.status_lbl.pack(pady=2)

        self.found_files = set()

    def log(self, text):
        self.log_text.insert(tk.END, text + "\n")
        self.log_text.see(tk.END)

    def set_buttons_state(self, state):
        self.btn_fast.config(state=state)
        self.btn_full.config(state=state)
        self.btn_custom.config(state=state)

    def check_file(self, filepath):
        try:
            if filepath in self.found_files or os.path.getsize(filepath) > 10 * 1024 * 1024:
                return

            with open(filepath, 'rb') as f:
                content = f.read()

            # 1. Проверка на точный чит
            for sig in EXACT_SIGNATURES:
                if sig in content:
                    self.found_files.add(filepath)
                    self.tree.insert("", tk.END, values=("🚨 ТОЧНЫЙ ЧИТ (LDR)", filepath))
                    self.log(f"[НАЙДЕН ЧИТ] {filepath}")
                    return

            # 2. Проверка на PE-инжектор
            matched_apis = [api for api in GENERIC_SUSPICIOUS if api in content]
            if len(matched_apis) >= 3:
                self.found_files.add(filepath)
                self.tree.insert("", tk.END, values=("⚠️ Подозрительный инжектор", filepath))
                self.log(f"[ИНЖЕКТОР] {filepath}")

        except Exception:
            pass

    def scan_directories(self, paths):
        self.set_buttons_state(tk.DISABLED)
        self.log("--- СКАНИРОВАНИЕ НАЧАТО ---")

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

        self.log(f"--- СКАНИРОВАНИЕ ЗАВЕРШЕНО (Проверено: {total_checked}) ---")
        self.status_lbl.config(text="Готово!")
        self.set_buttons_state(tk.NORMAL)

    def get_selected_path(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Внимание", "Сначала выберите файл из списка сверху (нажмите на него)!")
            return None
        return self.tree.item(selected_item[0])['values'][1]

    def open_file_folder(self):
        filepath = self.get_selected_path()
        if not filepath:
            return

        norm_path = os.path.normpath(filepath)
        if os.path.exists(norm_path):
            # Открывает проводник и сразу выделяет конкретный файл
            subprocess.run(f'explorer /select,"{norm_path}"')
        else:
            messagebox.showerror("Ошибка", "Файл больше не существует по этому пути!")

    def run_selected_file(self):
        filepath = self.get_selected_path()
        if not filepath:
            return

        norm_path = os.path.normpath(filepath)
        if not os.path.exists(norm_path):
            messagebox.showerror("Ошибка", "Файл не найден!")
            return

        if messagebox.askyesno("Подтверждение", f"Запустить файл?\n\n{norm_path}"):
            try:
                # Запускает скрипт через текущий интерпретатор Python
                subprocess.Popen([sys.executable, norm_path], cwd=os.path.dirname(norm_path))
                self.log(f"[ЗАПУЩЕН] {norm_path}")
            except Exception as e:
                messagebox.showerror("Ошибка запуска", str(e))

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
        if messagebox.askyesno("Диск C:", "Сканирование всего диска C: может занять 1-2 минуты. Начать?"):
            threading.Thread(target=self.scan_directories, args=(["C:\\"],), daemon=True).start()

    def start_custom_scan(self):
        folder = filedialog.askdirectory()
        if folder:
            threading.Thread(target=self.scan_directories, args=([folder],), daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerApp(root)
    root.mainloop()
