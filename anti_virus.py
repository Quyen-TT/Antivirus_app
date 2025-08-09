import os
import sys
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, simpledialog
import zipfile, tarfile, gzip, rarfile, py7zr, shutil
import queue
import requests

class VirusScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Virus Scanner v1.0.0")
        self.file_path = tk.StringVar()
        self.matched_strings = []
        self.action_queue = queue.Queue()
        self.is_prompt_open = False
        self._init_gui()

    def _init_gui(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(3, weight=1)
        self.root.rowconfigure(4, weight=0)
        tk.Label(self.root, text="Select a file to scan for viruses:").grid(row=0, column=0, pady=10, padx=10)

        tk.Entry(self.root, textvariable=self.file_path, width=70).grid(row=1, column=0, padx=10, pady=5, sticky="ew")

        button_frame = tk.Frame(self.root)
        button_frame.grid(row=2, column=0, pady=5)
        tk.Button(button_frame, text="Open File", command=self._browse_file).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Open Folder", command=self._browse_folder).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Scan", command=self._start_scan).pack(side=tk.LEFT, padx=5)

        self.output_text = scrolledtext.ScrolledText(self.root, width=90, height=25)
        self.output_text.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")

        self.view_details_button = tk.Button(self.root, text="View Details", command=self.view_details, state=tk.NORMAL)
        self.view_details_button.grid(row=4, column=0, pady=10)

    def _browse_file(self):
        filename = filedialog.askopenfilename(title="Select a file")
        if filename:
            self.file_path.set(filename)

    def _browse_folder(self):
        foldername = filedialog.askdirectory(title="Select a folder")
        if foldername:
            self.file_path.set(foldername)

    def _start_scan(self):
        file_path = self.file_path.get()
        if not (os.path.isfile(file_path) or os.path.isdir(file_path)):
            self._log_output("Please select a valid file or folder.")
            return
        self.output_text.delete(1.0, tk.END)
        self._log_output("===== Starting Scan =====\n")
        threading.Thread(target=self._run_scan, args=(file_path,), daemon=True).start()

    def _run_scan(self, file_path):
        if os.path.isfile(file_path):
            scan_paths = [file_path]
        else:
            scan_paths = [
                os.path.join(root, f)
                for root, _, files in os.walk(file_path)
                for f in files
            ]
    
        white_list_rules = self._get_yara_rules("white_list")
        black_list_rules = self._get_yara_rules("black_list")
        
        white_list_matches = []
        black_list_matches = []
        cuckoo_files = []
        extracted_dirs = []
        self.matched_strings.clear()
        
        for scan_file in scan_paths:
            if scan_file.endswith(('.zip', '.rar', '.7z', '.tar', '.gz')):
                self._log_output(f"Extracting and scanning compressed file: {scan_file}\n")
                extracted_dir = self._extract_file(scan_file)
                if extracted_dir:
                    extracted_dirs.append(extracted_dir)
                    extracted_files = [
                        os.path.join(root, f)
                        for root, _, files in os.walk(extracted_dir)
                        for f in files
                    ]
                    for extracted_file in extracted_files:
                        result = self._scan_file_with_yara(extracted_file, white_list_rules, black_list_rules)
                        if result == 'safe':
                            white_list_matches.append(extracted_file)
                        elif result == 'malware':
                            black_list_matches.append(extracted_file)
                        else:
                            cuckoo_files.append(extracted_file)
                else:
                    self._log_output(f"Failed to extract archive: {scan_file}\n")
            else:
                result = self._scan_file_with_yara(scan_file, white_list_rules, black_list_rules)
                if result == 'safe':
                    white_list_matches.append(scan_file)
                elif result == 'malware':
                    black_list_matches.append(scan_file)
                else:
                    cuckoo_files.append(scan_file)
        
        if black_list_matches:
            for detected_file in black_list_matches:
                self._prompt_action(detected_file)
            self.view_details_button.config(state=tk.NORMAL)
        
        for cuckoo_file in cuckoo_files:
            self._send_to_cuckoo(cuckoo_file)
        
        for extracted_dir in extracted_dirs:
            self._cleanup(extracted_dir)
        
        threat_count = len(black_list_matches)
        summary = (
            f"===== Scan Summary =====\n"
            f"\n- Total YARA rules: {len(white_list_rules) + len(black_list_rules)}\n"
            f"\n- Files matched white list: {len(white_list_matches)}\n"
            f"\n- Threats detected in {threat_count} file(s)\n"
            f"\n- Files sent to Cuckoo: {len(cuckoo_files)}\n"
        )
        self._log_output(summary)

    def _scan_file_with_yara(self, scan_file, white_list_rules, black_list_rules):
        self._log_output(f">> Scanning file: {scan_file}\n")
        
        white_list_matched = False
        for rule in white_list_rules:
            rule_name = os.path.basename(rule)
            yara_command = [self._get_yara_path(), '-s', '-p', '8', '-f', rule, scan_file]
            matched_strings = self._execute_yara(yara_command)

            if matched_strings:
                self._log_output(f"   - File is safe (matched white list rule: {rule_name})\n")
                self.matched_strings.append(f"YARA Rule: {rule_name} ({len(matched_strings)} matches)\n{'-'*50}")
                for match in matched_strings:
                    self.matched_strings.append(f"{match}")
                self.matched_strings.append('-'*50 + '\n')
                white_list_matched = True
                break 

        if white_list_matched:
            return 'safe'

        self._log_output(f"   - No matches found in white list.\n")

        # Check against black list rules
        black_list_matched = False
        for rule in black_list_rules:
            rule_name = os.path.basename(rule)
            yara_command = [self._get_yara_path(), '-s', '-p', '8', '-f', rule, scan_file]
            matched_strings = self._execute_yara(yara_command)

            if matched_strings:
                self._log_output(f"   - Malware detected (matched black list rule: {rule_name})\n")
                self.matched_strings.append(f"YARA Rule: {rule_name} ({len(matched_strings)} matches)\n{'-'*50}")
                for match in matched_strings:
                    self.matched_strings.append(f"{match}")
                self.matched_strings.append('-'*50 + '\n')
                black_list_matched = True
                break

        if not black_list_matched:
            self._log_output(f"   - No matches found in black list.\n")

        if black_list_matched:
            return 'malware'
        else:
            return 'unknown'

    def _execute_yara(self, command):
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            stdout, stderr = process.communicate()

            matched_strings = []
            if process.returncode == 0:
                if stdout:
                    matched_strings = stdout.splitlines()
                else:
                    matched_strings = []
            else:
                self._log_output(f"Error executing YARA: {stderr}")
            return matched_strings
        except Exception as e:
            self._log_output(f"Error executing YARA: {e}")
            return []

    def _send_to_cuckoo(self, file_path):
        self._log_output(f"Sending file to Cuckoo for analysis: {file_path}\n")
        
        cuckoo_api_url = "http://192.168.10.100:1337/tasks/create/file"
        api_token = "5r6pK0JFptvSGTM40Vzhkg"
        
        headers = {
            "Authorization": f"Bearer {api_token}"
        }
        
        try:
            with open(file_path, 'rb') as file_to_upload:
                files = {'file': (os.path.basename(file_path), file_to_upload)}
                response = requests.post(cuckoo_api_url, headers=headers, files=files)
                
                if response.status_code == 200:
                    self._log_output(f"File {file_path} successfully sent to Cuckoo.\n")
                else:
                    self._log_output(f"Failed to send file {file_path} to Cuckoo. Status code: {response.status_code}\n")
                    self._log_output(f"Response: {response.text}\n")
                    
        except Exception as e:
            self._log_output(f"Error sending file to Cuckoo: {e}\n")

    def view_details(self):
        if not self.matched_strings:
            messagebox.showinfo("No Details", "No matching strings were found.")
            return

        details_window = tk.Toplevel(self.root)
        details_window.title("Details")
        details_window.geometry("600x400")
        details_window.columnconfigure(0, weight=1)
        details_window.rowconfigure(0, weight=1)

        text_area = scrolledtext.ScrolledText(details_window, width=80, height=20)
        text_area.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        for line in self.matched_strings:
            text_area.insert(tk.END, line + "\n")
        text_area.configure(state='disabled') 

    def _prompt_action(self, file_path):
        self.action_queue.put(file_path) 
        self._process_next_action()

    def _process_next_action(self):
        if not self.is_prompt_open and not self.action_queue.empty():
            file_path = self.action_queue.get() 
            self.is_prompt_open = True 

            prompt_window = tk.Toplevel(self.root)
            prompt_window.title("Virus Detected")
            prompt_window.geometry("300x150")
            tk.Label(prompt_window, text="Virus detected. Choose an action:").pack(pady=10)
            tk.Button(prompt_window, text="Delete", command=lambda: self._handle_action("delete", file_path, prompt_window)).pack(pady=5)
            tk.Button(prompt_window, text="Freeze", command=lambda: self._handle_action("freeze", file_path, prompt_window)).pack(pady=5)
            prompt_window.protocol("WM_DELETE_WINDOW", lambda: self._on_prompt_close(prompt_window))

    def _on_prompt_close(self, prompt_window):
        prompt_window.destroy()
        self.is_prompt_open = False
        self._process_next_action() 

    def _handle_action(self, action, filename, prompt_window):
        prompt_window.destroy()
        self.is_prompt_open = False 
        if action == "delete":
            self._delete_file(filename)
        elif action == "freeze":
            self._freeze_file(filename)
        self._process_next_action() 

    def _delete_file(self, file_path):
        try:
            os.remove(file_path)
            self._log_output(f"- File '{file_path}' has been deleted.\n")
        except Exception as e:
            self._log_output(f"Failed to delete file: {e}")

    def _freeze_file(self, file_path):
        try:
            frozen_path = os.path.join(os.path.dirname(file_path), f"frozen_{os.path.basename(file_path)}")
            os.rename(file_path, frozen_path)
            subprocess.run(['icacls', frozen_path, '/deny', 'Everyone:(F)'], check=True)
            self._log_output(f"- File '{file_path}' has been frozen.\n")
        except Exception as e:
            self._log_output(f"Failed to freeze file: {e}")

    def _prompt_password(self):
        temp_parent = tk.Tk()
        temp_parent.withdraw() 

        try:
            password = simpledialog.askstring("Password Required", 
                                            "Enter password for encrypted file:", 
                                            show='*', parent=temp_parent)
            if password is None:
                self._log_output("Extraction canceled: No password provided.\n")
            return password.encode() if password else None
        finally:
 
            temp_parent.destroy()

    def _extract_file(self, file_path, depth=1, max_depth=5):
        if not file_path.endswith(('.zip', '.rar', '.7z', '.tar', '.gz')) or depth > max_depth:
            return file_path

        extract_dir = os.path.join(os.path.dirname(file_path), f"extracted_files_level_{depth}")
        os.makedirs(extract_dir, exist_ok=True)

        try:
            if file_path.endswith('.zip'):
                with zipfile.ZipFile(file_path, 'r') as zf:
                    try:
                        zf.extractall(extract_dir)
                    except RuntimeError as e:
                        if "encrypted" in str(e).lower():
                            password = self._prompt_password()
                            if password:
                                zf.extractall(extract_dir, pwd=password)
                        else:
                            raise e

            elif file_path.endswith('.rar'):
                with rarfile.RarFile(file_path) as rf:
                    try:
                        rf.extractall(extract_dir)
                    except rarfile.BadRarFile as e:
                        if "password" in str(e).lower():
                            password = self._prompt_password()
                            if password:
                                rf.extractall(extract_dir, pwd=password)
                        else:
                            raise e

            elif file_path.endswith('.7z'):
                with py7zr.SevenZipFile(file_path, mode='r') as zf:
                    try:
                        zf.extractall(path=extract_dir)
                    except py7zr.exceptions.PasswordRequired:
                        password = self._prompt_password()
                        if password:
                            zf.extractall(path=extract_dir, password=password)

            elif file_path.endswith('.tar'):
                with tarfile.open(file_path, 'r') as tf:
                    tf.extractall(extract_dir)

            elif file_path.endswith('.gz'):
                with gzip.open(file_path, 'rb') as gf:
                    with open(os.path.join(extract_dir, os.path.basename(file_path)[:-3]), 'wb') as out_file:
                        out_file.write(gf.read())

            for root, _, files in os.walk(extract_dir):
                for f in files:
                    extracted_file_path = os.path.join(root, f)
                    if extracted_file_path.endswith(('.zip', '.rar', '.7z', '.tar', '.gz')) and depth < max_depth:
                        self._extract_file(extracted_file_path, depth + 1, max_depth)

            return extract_dir

        except Exception as e:
            self._log_output(f"Extraction failed: {e}")
            return file_path
            
    def _cleanup(self, path):
        try:
            shutil.rmtree(path)
        except Exception as e:
            self._log_output(f"Cleanup error: {e}")

    def _get_yara_path(self):
        base_path = getattr(sys, '_MEIPASS', os.path.dirname(__file__))
        return os.path.join(base_path, "yara.exe")

    def _get_yara_rules(self, rule_type=None):
        base_path = getattr(sys, '_MEIPASS', os.path.dirname(__file__))
        rules_dir = os.path.join(base_path, 'yara_rules')
        
        if rule_type == "white_list":
            sub_dir = "white_list"
        else:
            sub_dir = "black_list"

        sub_dir_path = os.path.join(rules_dir, sub_dir)
        if not os.path.exists(sub_dir_path):
            self._log_output(f"Rules directory not found: {sub_dir_path}")
            return []
        return [os.path.join(sub_dir_path, f) for f in os.listdir(sub_dir_path) if f.endswith(('.yar', '.yara'))]
    
    def _get_winrar_path(self):
        base_path = getattr(sys, '_MEIPASS', os.path.dirname(__file__))
        return os.path.join(base_path, "winrar.exe")

    def _get_7zip_path(self):
        base_path = getattr(sys, '_MEIPASS', os.path.dirname(__file__))
        return os.path.join(base_path, "7z.exe")

    def _log_output(self, message):
        self.output_text.insert(tk.END, message + '\n')
        self.output_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = VirusScannerApp(root)
    root.mainloop()