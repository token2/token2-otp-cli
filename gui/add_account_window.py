import tkinter as tk
import base64
import os
import sys
import subprocess
import tkinter.messagebox

class AddAccountWindow:
    def __init__(self, root, parent):
        self.root = root
        self.parent = parent
        self.root.title("Add TOTP Account")

        self.root.geometry("600x500")  # Adjusted window size

        self.app_label = tk.Label(root, text="App Name:")
        self.app_label.pack(anchor="w", padx=20, pady=10)

        self.app_entry = tk.Entry(root)
        self.app_entry.pack(fill="x", padx=20, pady=(0, 10))

        self.account_label = tk.Label(root, text="Account Name:")
        self.account_label.pack(anchor="w", padx=20, pady=10)

        self.account_entry = tk.Entry(root)
        self.account_entry.pack(fill="x", padx=20, pady=(0, 10))

        self.secret_label = tk.Label(root, text="Secret:")
        self.secret_label.pack(anchor="w", padx=20, pady=10)

        self.secret_entry = tk.Entry(root)
        self.secret_entry.pack(fill="x", padx=20, pady=(0, 10))

        self.random_button = tk.Button(root, text="Random", command=self.generate_random_secret)
        self.random_button.pack(anchor="w", padx=20)

        self.require_checkbox_var = tk.BooleanVar()  # Define a Tkinter BooleanVar
        self.require_checkbox = tk.Checkbutton(root, text="Require Button", variable=self.require_checkbox_var)
        self.require_checkbox.pack(anchor="w", padx=20, pady=10)

        self.options_frame = tk.Frame(root)
        self.options_frame.pack(anchor="w", padx=20, pady=10)

        self.hash_var = tk.StringVar(value="SHA1")
        self.hash_label = tk.Label(self.options_frame, text="Hash Algorithm:")
        self.hash_label.pack(side="left", padx=5)

        self.hash_options = ["SHA1", "SHA256"]
        self.hash_menu = tk.OptionMenu(self.options_frame, self.hash_var, *self.hash_options)
        self.hash_menu.pack(side="left", padx=10)

        self.otp_length_var = tk.IntVar(value=6)
        self.otp_length_label = tk.Label(self.options_frame, text="OTP Length:")
        self.otp_length_label.pack(side="left", padx=5)

        self.otp_length_options = [4, 6, 8]
        self.otp_length_menu = tk.OptionMenu(self.options_frame, self.otp_length_var, *self.otp_length_options)
        self.otp_length_menu.pack(side="left", padx=10)

        self.time_step_var = tk.IntVar(value=30)
        self.time_step_label = tk.Label(root, text="Time Step:")
        self.time_step_label.pack(anchor="w", padx=20, pady=(0, 10))

        self.time_step_options = [30, 60]
        self.time_step_menu = tk.OptionMenu(root, self.time_step_var, *self.time_step_options)
        self.time_step_menu.pack(anchor="w", padx=20, pady=(0, 10))

        self.add_button = tk.Button(root, text="Add", command=self.add_account, font=("Helvetica", 14, "bold"), width=15)
        self.add_button.pack(anchor="e", padx=20, pady=20)

    def generate_random_secret(self):
        random_secret = base64.b32encode(os.urandom(20)).decode("utf-8")
        self.secret_entry.delete(0, "end")
        self.secret_entry.insert(0, random_secret)
 
    def validate_input(self):
     #app_name = self.app_entry.get()
     #account_name = self.account_entry.get()
     #secret = self.secret_entry.get()
     app_name = self.app_entry.get().replace(" ", "")  # Remove spaces
     account_name = self.account_entry.get().replace(" ", "")  # Remove spaces
     secret = self.secret_entry.get().replace(" ", "").upper()  # Remove spaces and capitalize

     if not (app_name and len(app_name) <= 20):
        self.show_error("App name must not be empty and should have 20 characters or less.")
        return False

     if not (account_name and len(account_name) <= 32):
        self.show_error("Account name must not be empty and should have 32 characters or less.")
        return False

     try:
        # Decode the secret using base32 and catch decoding errors
        decoded_secret = base64.b32decode(secret, casefold=True, map01=None)
     except base64.binascii.Error:
        self.show_error("Invalid secret format. Make sure it's a valid base32 encoded string.")
        return False

     if not (16 <= len(secret) <= 64):
        self.show_error("Secret should be between 16 and 64 base32 characters.")
        return False

     return True

     
 
     

    
    
    def show_error(self, message):
        error_window = tk.Toplevel(self.root)
        error_window.title("Validation Error")
        error_label = tk.Label(error_window, text=message, padx=10, pady=10)
        error_label.pack()
        ok_button = tk.Button(error_window, text="OK", command=error_window.destroy)
        ok_button.pack()

    def add_account(self):
        if not self.validate_input():
            return

        #app_name = self.app_entry.get()
        #account_name = self.account_entry.get()
        #secret = self.secret_entry.get()
        app_name = self.app_entry.get().replace(" ", "")  # Remove spaces
        account_name = self.account_entry.get().replace(" ", "")  # Remove spaces
        secret = self.secret_entry.get().replace(" ", "").upper()  # Remove spaces and capitalize      


        # Use .get() method on a Tkinter variable to get the value of the Checkbutton
        require_button = self.require_checkbox_var.get()

        hash_algorithm = self.hash_var.get()
        otp_length = self.otp_length_var.get()
        time_step = self.time_step_var.get()

        command = [
            sys.executable,
            "app.py",
            "write_entry",
            "--type", "TOTP",
            "--algorithm", hash_algorithm,
            "--timestep", str(time_step),
            "--code-length", str(otp_length),
            "--app-name", app_name,
            "--account-name", account_name,
            "--seed", secret
                ]

        if require_button:
            command.append("--button-required")

        

        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
            if not output:
                self.root.destroy()  # Close Add Account window
                self.parent.fetch_data()  # Run fetch_data in the parent window
            else:
                tk.messagebox.showinfo("Output", output)
        except subprocess.CalledProcessError as e:
            tk.messagebox.showerror("Error", f"An error occurred: {e.output}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AddAccountWindow(root, None)  # Replace None with the parent window instance
    root.mainloop()
