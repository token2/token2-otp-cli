import tkinter as tk
import tkinter.ttk as ttk
from tkinter import *
from tkinter import messagebox  # Import messagebox from tkinter
import subprocess
import os
import sys
import json
import pyperclip
from datetime import datetime
import threading
import time
import random
import base64
import add_account_window
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("TOTP Viewer")
        if os.name == "posix":  # Linux or macOS
            img = PhotoImage(file="icon.png") #16 px image
            img_l = PhotoImage(file="icon_l.png") #32 px image   
            self.root.iconphoto(False, img_l, img)
            
        elif os.name == "nt":  # Windows
            self.root.iconbitmap("t2.ico")
            
        
        self.style = ttk.Style()
        self.style.configure("Custom.Treeview.Heading",background='gray', font=('Helvetica', 15))  # Header font
        self.style.configure("Custom.Treeview", font=("Helvetica", 15))  # Default cell font
        self.style.configure("Custom.Treeview.Cell", font=("Helvetica", 16))  # Custom cell font

        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        #self.fetch_button = ttk.Button(root, text="Fetch data", command=self.fetch_data)
        #self.fetch_button.pack()

        self.table = ttk.Treeview(root, columns=("App Name", "Account Name", "Timestep", "Countdown", "OTP Code"), show="headings")
        self.table.heading("App Name", text="App Name")
        self.table.heading("Account Name", text="Account Name")
        self.table.heading("Timestep", text="Timestep", anchor=tk.CENTER)
        self.table.heading("Countdown", text="Countdown", anchor=tk.CENTER)
        self.table.heading("OTP Code", text="OTP Code", anchor=tk.CENTER)
        self.table.column("App Name", width=100)  # Adjust the width as needed
        self.table.column("Account Name", width=100)  # Adjust the width as needed
        self.table.column("Timestep", width=100)  # Adjust the width as needed
        self.table.column("Countdown", width=100)  # Adjust the width as needed
        self.table.column("OTP Code", width=150)  # Adj
        self.scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=self.table.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.table.configure(yscrollcommand=self.scrollbar.set)
        self.table.bind("<Double-1>", self.copy_otp)

        #self.table.pack()
        self.table.pack(fill='both', expand=True)
        self.menu = tk.Menu(root)
        root.config(menu=self.menu)
        # Configure column and row weights for responsiveness
        root.columnconfigure(0, weight=1)  # Make the first column (where the table is) expandable
        root.rowconfigure(0, weight=1)     # Make the first row expandable

        self.file_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Add Account", command=self.open_add_account_window)
        self.file_menu.add_command(label="Delete Account", command=self.delete_account)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Erase All Accounts", command=self.erase_all_accounts)
        self.file_menu.add_command(label="Generate Test Accounts", command=self.generate_test_accounts)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Refresh", command=self.fetch_data_manually)  # Add this line
        
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=root.quit)
        # Help menu
        self.help_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Help", menu=self.help_menu)
        self.help_menu.add_command(label="Readme", command=self.open_readme)
        self.help_menu.add_command(label="About", command=self.show_about)
        
        
        self.update_countdowns_thread = None
        self.check_countdown_zero_thread = None
        self.fetch_data_thread = None

        self.fetch_data()  # Initial data fetch
        self.update_time()
        self.start_update_countdowns_thread()
        self.start_check_countdown_zero_thread()
    

    def generate_test_accounts(self):
        creative_names = [
            "Umbrella Corp",
            "Innovative",
            "Wayne Indus",
            "Oscorp",
            "Stark Ind",
            "UAC Doom",
            "Spaceleys",
            "Cyberdyne",
            "Zorin Ind",
            "Momcorp",
            "Acme",
            "Contoso",
            "ASAN Xidmet",
            "lAzer.Net",
            "OCMP",            
            "RoboCop"
        ]
        real_account_names = [
            "Zuendel Anderson",
            "Zeim Johnson",
            "Yorston Edwards",
            "Yuill Paterson",
            "Zellers Karlsson",
            "York Patel",
            "Zolnierz Pettersen",
            "Zuehlke Walker",
            "Yaddow Brown",
            "Zacherl Halvorsen",
            "Zucchero Hansson",
            "Magripa Haripulla",
            "Stephen Bandera",
            "Deonardo Li Acprio",            
            "Kumys Ispaket"
            # ... Add more real names as needed
        ]
        self.status_var.set(f"⌛ Creating test accounts")
        confirm = messagebox.askyesno(
            "Generate Test Accounts",
            "Are you sure you want to populate the device with test TOTP accounts?"
            "\nDo not use this if you have any production accounts already on the device."
        )
        if confirm:
            
            for app_name in creative_names:
                account_name = random.choice(real_account_names)
                secret = os.urandom(20)
                seed = base64.b32encode(secret).decode("utf-8")
                timestep = random.choice(["30", "60"])
                code_length = random.choice(["6", "8"])
                algorithm = random.choice(["SHA1", "SHA256"])

                cmd = [
                    sys.executable,
                    "app.py",
                    "write_entry",
                    "--type", "TOTP",
                    "--algorithm", algorithm,
                    "--timestep", timestep,
                    "--code-length", code_length,
                    
                    "--app-name", app_name,
                    "--account-name", account_name,
                    "--seed", seed,
                ]
                
                button_required = random.choice([True, False])
                if button_required:
                    cmd.append("--button-required")
                
                try:
                    subprocess.check_output(cmd)
                except subprocess.CalledProcessError as e:
                    messagebox.showerror("Error", f"An error occurred: {e}")
                    return

            messagebox.showinfo("Success", "Test accounts have been generated.")
            # Fetch data after successful delete
            self.table.delete(*self.table.get_children())
            self.fetch_data()
            
        
    def erase_all_accounts(self):
        self.status_var.set(f"⌛ Erasing all accounts. Button press needed to confirm")
        confirm = messagebox.askyesno("Erase All Accounts", "Are you sure you want to erase all accounts?\r\nAfter confirming touch the button/sensor on the device to confirm the operation.\r\nTo cancel, unplug the device.")
        if confirm:
            try:
                subprocess.check_output([sys.executable, "app.py", "erase_all"])
                messagebox.showinfo("Success", "All accounts have been erased.")
                self.fetch_data()
                 # Fetch data after successful delete
                self.table.delete(*self.table.get_children())
                self.fetch_data()
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"An error occurred: {e}")

    # ... (rest of the methods)        
        
    def open_readme(self):
        readme_path = "gui/README.GUI.html"
        if os.name == "posix":  # Linux or macOS
            subprocess.Popen(["xdg-open", readme_path])
        elif os.name == "nt":  # Windows
            subprocess.Popen(["start", "", readme_path], shell=True)

    def show_about(self):
        about_text = "GUI Wrapper App for Token2 Python T2F2 OTP CLI Tool\r\n(c) Copyright Token2 Sarl\r\nMIT License"
        messagebox.showinfo("About", about_text)
        
    def delete_account(self):
        selected_item = self.table.selection()[0]
        app_name = self.table.item(selected_item, "values")[0]
        account_name = self.table.item(selected_item, "values")[1]

        confirm = messagebox.askyesno("Delete Account", f"Are you sure you want to delete '{app_name}' account '{account_name}'?")
        if confirm:
            process = subprocess.Popen([sys.executable, "app.py", "delete_entry", "--app-name", app_name, "--account-name", account_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            

            if stderr:
                messagebox.showerror("Error", stderr.decode("utf-8"))
            else:
                if stdout:
                    messagebox.showinfo("Delete Account", stdout.decode("utf-8"))
                else:
                    messagebox.showinfo("Delete Account", "Account deleted successfully.")
            # Fetch data after successful delete
                self.table.delete(*self.table.get_children())            
                self.fetch_data()        

# ... 

    def fetch_data_manually(self):
        self.status_var.set(f"⌛ Fetching OTP list from the device")
        self.fetch_data_thread_func()

        
    def open_add_account_window(self):
        add_account_root = tk.Toplevel(self.root)
        add_account_app = add_account_window.AddAccountWindow(add_account_root, self)



    def start_update_countdowns_thread(self):
        self.update_countdowns_thread = threading.Thread(target=self.update_countdowns)
        self.update_countdowns_thread.daemon = True
        self.update_countdowns_thread.start()

    def start_check_countdown_zero_thread(self):
        self.check_countdown_zero_thread = threading.Thread(target=self.check_countdown_zero)
        self.check_countdown_zero_thread.daemon = True
        self.check_countdown_zero_thread.start()

    def populate_table(self, json_data):
        data = json.loads(json_data)
        for entry in data["entries"]:
            app_name = entry["app_name"]
            account_name = entry["account_name"]
            timestep = entry.get("timestep", "")
            otp_code = entry["otp_code"]

            existing_items = self.table.get_children()
            for item in existing_items:
                values = self.table.item(item, 'values')
                if values[0] == app_name and values[1] == account_name:
                    self.table.item(item, values=(app_name, account_name, timestep, "", otp_code))
                    break
            else:
                last_item = self.table.insert("", "end", values=(app_name, account_name, timestep, "", otp_code))
                self.table.item(last_item, tags=("otp_font",))

    def fetch_data(self):
        if self.fetch_data_thread and self.fetch_data_thread.is_alive():
            return

        self.fetch_data_thread = threading.Thread(target=self.fetch_data_thread_func)
        self.fetch_data_thread.start()

    def fetch_data_thread_func(self):
        self.status_var.set(f"⌛ Fetching OTP list from the device")
        try:
            if os.name == "posix":  # Linux or macOS
             output_bytes = subprocess.check_output([sys.executable, "app.py", "--json", "get_all"])
            elif os.name == "nt":  # Windows
             output_bytes = subprocess.check_output([sys.executable, "app.py", "--json", "get_all"], shell=True)
            time.sleep(0.2)

            output_str = output_bytes.decode('utf-8')
            self.populate_table(output_str)
            try:
              if os.name == "posix":  # Linux or macOS
                output_sn_bytes = subprocess.check_output([sys.executable, "app.py", "read_serial_no"])
              elif os.name == "nt":  # Windows
                output_sn_bytes = subprocess.check_output([sys.executable, "app.py", "read_serial_no"], shell=True)
                serialno=""
              serialno = output_sn_bytes.decode('utf-8')
            except(subprocess.CalledProcessError):
              serialno=""



            total_rows = len(self.table.get_children())
            self.root.title(f"TOTP Viewer ( {total_rows} accounts - {serialno})")
            self.status_var.set(f"✅︎ OTP Data retrieved")
            self.root.after(800, self.clear_status)
        except subprocess.CalledProcessError as e:
            self.status_var.set(f"⚠ Error communicating with the device. OTPs will be retrieved on next refresh")
            #self.root.after(30000, self.clear_status)            
            #print("Error fetching data:", e)
            #self.fetch_data_thread_func()
            
            

    def copy_otp(self, event):
        selected_item = self.table.selection()[0]
        otp_code = self.table.item(selected_item, "values")[4]
        account_name = self.table.item(selected_item, "values")[1]
        app_name = self.table.item(selected_item, "values")[0]

        if otp_code and any(char.isdigit() for char in otp_code):
            pyperclip.copy(otp_code)
            self.status_var.set("OTP Copied")
            self.root.after(3000, self.clear_status)
        elif otp_code == "None":
        #read_entry --app-name 'Test app' --account-name 'Test account'
         if os.name == "posix":  # Linux or macOS
            subprocess.Popen([sys.executable, "button_otp.py", "read_entry", "--account-name",account_name, "--app-name",app_name ])  #  
         elif os.name == "nt":  # Windows
            subprocess.Popen([sys.executable, "button_otp.py", "read_entry", "--account-name",account_name, "--app-name",app_name ], creationflags=subprocess.CREATE_NEW_CONSOLE)  #  
            
        else:
            self.status_var.set("Invalid OTP")

    def clear_status(self):
        self.status_var.set("")

    def update_countdowns(self):
        current_time = datetime.now()
        for item_id in self.table.get_children():
            timestep = int(self.table.item(item_id, "values")[2])
            if timestep == 30:
                seconds_until_next = 30 - (current_time.second % 30)
            elif timestep == 60:
                seconds_until_next = 60 - current_time.second
            else:
                seconds_until_next = 0

            minutes, seconds = divmod(seconds_until_next, 60)
            countdown_value = f"{minutes:02}:{seconds:02}"
            self.table.item(item_id, values=(self.table.item(item_id, "values")[0], self.table.item(item_id, "values")[1], self.table.item(item_id, "values")[2], countdown_value, self.table.item(item_id, "values")[4]))

        self.root.after(1000, self.update_countdowns)  # Update countdowns every second
        

    def check_countdown_zero(self):
        while True:
            for item_id in self.table.get_children():
                countdown_value = self.table.item(item_id, "values")[3]
                if countdown_value == "00:00":
                    self.fetch_data_thread_func()
                    self.fetch_data()
                    break
            time.sleep(1)
            
            
    def update_time(self):
        current_time = time.strftime("%Y-%m-%d %H:%M:%S")
        #self.status_var.set(f"Current Time: {current_time}")
        for item_id in self.table.get_children():
                countdown_value = self.table.item(item_id, "values")[3]
                minutes, seconds = map(int, countdown_value.split(":")) if countdown_value else (0, 0)  # Convert MM:SS to integers or set to (0, 0)
                #self.status_var.set(f"Minutes: {minutes} {seconds}")
                
                if minutes == 0 and seconds <= 1:
                     
                    #self.fetch_data()
                    self.fetch_data_thread_func()
                    
                    break
        self.root.after(1000, self.update_time)         

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)

    def on_closing():
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
