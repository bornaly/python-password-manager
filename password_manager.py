"""
Password Manager Script
Developed by: Faruk Ahmed
Version: 1.0.0
Date: January 2025

Description:
A comprehensive password manager with encryption, CRUD operations, email integration, and data export features.

Contact:
GitHub: https://github.com/bornaly
Email: bornaly@gmail.com
"""

import tkinter as tk
import webbrowser
from tkinter import ttk, messagebox, Menu, filedialog
import sqlite3
import bcrypt
from email.mime.text import MIMEText
import smtplib
from email.header import Header
from email.utils import formataddr
import logging
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os
import base64
from PIL import Image, ImageTk
import pandas as pd


class SupplementClass:
    """
    Utility class for handling encryption, database operations, logging, and other supplementary tasks.
    """

    ADMIN_EMAIL = None
    LOG_DIR = "logs"
    DB_NAME = "password_manager.db"
    ICON_FILE = "safe_icon.ico"
    ICON_FALLBACK_FILE = "safe_icon.png"
    SECRET_KEY = b'16ByteSecretKey!'  # 16-byte key for AES encryption

    @classmethod
    def save_sender_credentials(cls, email, password):
        """Save sender email credentials to the database."""
        try:
            encrypted_password = cls.encrypt_data(password)  # Encrypt the password
            conn = sqlite3.connect(cls.DB_NAME)
            cursor = conn.cursor()

            # Delete any existing sender credentials to ensure only one record
            cursor.execute("DELETE FROM sender_credentials")

            # Insert the new credentials
            cursor.execute(
                "INSERT INTO sender_credentials (email, encrypted_password) VALUES (?, ?)",
                (email, encrypted_password)
            )
            conn.commit()
            conn.close()
            logging.info("Sender email credentials saved successfully.")
        except Exception as e:
            logging.error(f"Failed to save sender email credentials: {e}")
            raise


    @classmethod
    def init_logging(cls):
        """Initialize the logging system."""
        if not os.path.exists(cls.LOG_DIR):
            os.makedirs(cls.LOG_DIR)

        log_file = os.path.join(cls.LOG_DIR, f"{datetime.now().strftime('%Y-%m-%d')}.log")
        logging.basicConfig(
            filename=log_file,
            level=logging.ERROR,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
        cls.cleanup_old_logs()

    @classmethod
    def cleanup_old_logs(cls):
        """Remove log files older than 3 days."""
        log_files = sorted(
            [os.path.join(cls.LOG_DIR, f) for f in os.listdir(cls.LOG_DIR) if f.endswith(".log")],
            key=os.path.getmtime
        )
        while len(log_files) > 3:
            os.remove(log_files.pop(0))

    @staticmethod
    def prepare_icon():
        """
        Prepare and return the icon path for use in the application.
        Converts `.ico` to `.png` if needed and checks for valid paths.
        """
        try:
            # Use .png if available
            if os.path.exists("safe_icon.png"):
                return "safe_icon.png"

            # Convert .ico to .png if .png is missing
            if os.path.exists("safe_icon.ico"):
                img = Image.open("safe_icon.ico")
                img.save("safe_icon.png", format="PNG")
                return "safe_icon.png"

            # Convert .ico to .jpg as a fallback
            if os.path.exists("safe_icon.ico"):
                img = Image.open("safe_icon.ico")
                img.save("safe_icon.jpg", format="JPEG")
                return "safe_icon.jpg"

            logging.error("Icon file not found.")
            return None
        except Exception as e:
            logging.error(f"Error preparing icon: {e}")
            return None

    @classmethod
    def init_db(cls):
        """Initialize the database and create necessary tables."""
        conn = sqlite3.connect(cls.DB_NAME)
        cursor = conn.cursor()

        # Create or update the necessary tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id TEXT NOT NULL,
                hashed_password TEXT NOT NULL,
                original_password TEXT NOT NULL,
                target_name TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id TEXT NOT NULL,
                encrypted_password TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sender_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                encrypted_password TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS app_config (
                config_key TEXT PRIMARY KEY,
                config_value TEXT
            )
        """)
        conn.commit()
        conn.close()

    @classmethod
    def get_admin_email(cls):
        """
        Retrieve the admin email (ADMIN_EMAIL) from the database.
        Returns:
            str: The admin email if found, raises an error otherwise.
        """
        try:
            conn = sqlite3.connect(cls.DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT config_value FROM app_config WHERE config_key = 'ADMIN_EMAIL'")
            result = cursor.fetchone()
            conn.close()

            if result and result[0]:
                return result[0]
            else:
                raise ValueError("Admin email is not set in the database.")
        except sqlite3.Error as e:
            logging.error(f"Database error while retrieving admin email: {e}")
            raise ValueError("Failed to retrieve admin email.")


    @classmethod
    def save_admin_email(cls, admin_email):
        """
        Save or update the admin email (ADMIN_EMAIL) in the database.
        """
        try:
            conn = sqlite3.connect(cls.DB_NAME)
            cursor = conn.cursor()

            # Upsert the ADMIN_EMAIL into the app_config table
            cursor.execute("""
                INSERT INTO app_config (config_key, config_value)
                VALUES ('ADMIN_EMAIL', ?)
                ON CONFLICT(config_key) DO UPDATE SET config_value=excluded.config_value
            """, (admin_email,))
            conn.commit()
            conn.close()
            logging.info("Admin email saved successfully.")
        except Exception as e:
            logging.error(f"Failed to save admin email: {e}")
            raise ValueError("Failed to save admin email.")


    @classmethod
    def encrypt_data(cls, data):
        """Encrypt data using AES."""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(cls.SECRET_KEY), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + encrypted_data).decode()

    @classmethod
    def decrypt_data(cls, encrypted_data):
        """Decrypt AES-encrypted data."""
        data = base64.b64decode(encrypted_data)
        iv = data[:16]
        encrypted_content = data[16:]
        cipher = Cipher(algorithms.AES(cls.SECRET_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_content) + decryptor.finalize()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()

    @classmethod
    def save_admin_credentials(cls, admin_id, password):
        """Save encrypted admin credentials to the database."""
        encrypted_password = cls.encrypt_data(password)
        conn = sqlite3.connect(cls.DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO admin (admin_id, encrypted_password) VALUES (?, ?)",
                       (admin_id, encrypted_password))
        conn.commit()
        conn.close()

    @classmethod
    def get_admin_password(cls, admin_id):
        """Retrieve and decrypt the admin password."""
        conn = sqlite3.connect(cls.DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_password FROM admin WHERE admin_id = ?", (admin_id,))
        result = cursor.fetchone()
        conn.close()
        if result:
            return cls.decrypt_data(result[0])
        raise ValueError("Admin user not found!")

    @classmethod
    def get_sender_credentials(cls):
        """
        Retrieve the sender email credentials from the database.
        Returns:
            tuple: (email, decrypted_password) if credentials exist, raises a ValueError otherwise.
        """
        try:
            conn = sqlite3.connect(cls.DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT email, encrypted_password FROM sender_credentials LIMIT 1")
            result = cursor.fetchone()
            conn.close()

            if result:
                email = result[0]
                encrypted_password = result[1]
                if email and encrypted_password:
                    # Decrypt the password
                    decrypted_password = cls.decrypt_data(encrypted_password)
                    return email, decrypted_password
                else:
                    logging.error("Invalid sender credentials found in the database.")
                    raise ValueError("Sender credentials are incomplete or corrupted.")
            else:
                logging.error("No sender credentials found in the database.")
                raise ValueError("Sender credentials are not set! Please configure the sender email.")
        except sqlite3.Error as db_error:
            logging.error(f"Database error while retrieving sender credentials: {db_error}")
            raise ValueError("Failed to retrieve sender credentials due to a database error.")
        except Exception as e:
            logging.error(f"Unexpected error while retrieving sender credentials: {e}")
            raise ValueError("An unexpected error occurred while retrieving sender credentials.")


    @classmethod
    def send_recovery_email(cls):
        """
        Send a recovery email with admin credentials.
        """
        try:
            # Fetch sender credentials
            sender_email, sender_password = cls.get_sender_credentials()

            # Fetch admin email from the database
            admin_email = cls.get_admin_email()

            # Get the admin password
            admin_password = cls.get_admin_password("admin")
            email_body = f"Your admin credentials:\n\nUsername: admin\nPassword: {admin_password}"
            msg = MIMEText(email_body, 'plain', 'utf-8')
            msg["Subject"] = Header("Password Manager Admin Recovery", 'utf-8')
            msg["From"] = formataddr(("Password Manager", sender_email))
            msg["To"] = admin_email

            # Send the email
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(sender_email, sender_password)
                server.sendmail(msg["From"], [msg["To"]], msg.as_string())

            messagebox.showinfo("Success", "Recovery email sent successfully!")
        except ValueError as ve:
            logging.error(f"Validation error: {ve}")
            messagebox.showerror("Error", str(ve))
        except Exception as e:
            logging.error(f"Failed to send recovery email: {e}")
            messagebox.showerror("Error", f"Failed to send recovery email: {e}")


class PasswordManagerGUI:
    """
    GUI for Password Manager, including Tools and Maintenance menus with CRUD functionality.
    """

    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager 2.0")
        self.root.geometry("900x775")  # Set the window size
        self.center_window(self.root)  # Center the window
        self.root.configure(bg="#e6f7ff")

        # Set the window as visible and ensure focus
        self.root.lift()
        self.root.attributes("-topmost", True)
        self.root.attributes("-topmost", False)


        # Initialize logging, database, and icon
        icon_path = SupplementClass.prepare_icon()
        if icon_path:
            self.root.iconphoto(True, tk.PhotoImage(file=icon_path))


        SupplementClass.init_logging()  # Initialize logging system
        logging.info("Password Manager initialized. Developed by Faruk Ahmed.")  # Log initialization
        SupplementClass.init_db()  # Initialize database


        # Check for credentials and launch the appropriate windows
        if not self.check_sender_credentials():
            self.setup_sender_email()
            # Show splash screen first, then main UI
            self.show_splash_screen()
        elif not self.check_admin_credentials():
            # Show splash screen first, then main UI
            self.show_splash_screen()
            self.setup_admin_credentials()
        else:
            self.authenticate_admin()
            # Show splash screen first, then main UI
            self.show_splash_screen()



    @staticmethod
    def check_sender_credentials():
        conn = sqlite3.connect(SupplementClass.DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM sender_credentials")
        sender_exists = cursor.fetchone()[0] > 0
        conn.close()
        return sender_exists

    @staticmethod
    def check_admin_credentials():
        conn = sqlite3.connect(SupplementClass.DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM admin")
        admin_exists = cursor.fetchone()[0] > 0
        conn.close()
        return admin_exists

    def setup_admin_credentials(self):
        """
        Set up a window for the user to input admin credentials.
        Ensures the window is centered relative to the main Password Manager window.
        """

        def save_admin():
            admin_id = admin_id_entry.get().strip()
            admin_password = admin_password_entry.get().strip()
            if not admin_id or not admin_password:
                messagebox.showerror("Error", "Both fields are required!")
                return
            SupplementClass.save_admin_credentials(admin_id, admin_password)
            messagebox.showinfo("Success", "Admin credentials saved successfully!",parent=self.root) # Centered messagebox
            admin_window.destroy()
            self.authenticate_admin()  # Show Admin Login window after saving credentials

        # Create the admin credentials setup window
        admin_window = tk.Toplevel(self.root)
        admin_window.title("Setup Admin Credentials")
        admin_window.configure(bg="#d1e7ff")
        self.center_window(admin_window, 400, 250)

        admin_window.transient(self.root)
        admin_window.grab_set()
        admin_window.focus_force()

        tk.Label(admin_window, text="Create New Admin ID:", font=("Helvetica", 12), bg="#d1e7ff").pack(pady=10)
        admin_id_entry = ttk.Entry(admin_window, width=30)
        admin_id_entry.pack(pady=5)

        tk.Label(admin_window, text="Create New Admin Password:", font=("Helvetica", 12), bg="#d1e7ff").pack(pady=10)
        admin_password_entry = ttk.Entry(admin_window, width=30, show="*")
        admin_password_entry.pack(pady=5)

        save_button = ttk.Button(admin_window, text="Save Admin", command=save_admin)
        save_button.pack(pady=20)
        admin_window.bind("<Return>", lambda event: save_button.invoke())
        save_button.focus_set()

    # import webbrowser
    # from tkinter import messagebox

    def show_splash_screen(self):
        """
        Display a splash screen for 15 seconds, centered on the Password Manager window.
        """
        logging.info("Password Manager initialized. Developed by Faruk Ahmed.")  # Log initialization

        # Create the splash screen as a Toplevel window
        splash = tk.Toplevel(self.root)
        splash.title("Welcome")
        splash.configure(bg="#d1e7ff")
        splash.resizable(False, False)

        # Center the splash screen on the main Password Manager window
        splash_width = 500
        splash_height = 400
        root_x = self.root.winfo_x()
        root_y = self.root.winfo_y()
        root_width = self.root.winfo_width()
        root_height = self.root.winfo_height()

        splash_x = root_x + (root_width // 2) - (splash_width // 2)
        splash_y = root_y + (root_height // 2) - (splash_height // 2)
        splash.geometry(f"{splash_width}x{splash_height}+{splash_x}+{splash_y}")

        # Attach the splash screen to the main window
        splash.transient(self.root)
        splash.grab_set()  # Block interaction with the main window

        # Add content to the splash screen
        tk.Label(
            splash,
            text="Welcome to Password Manager 2.0",
            font=("Helvetica", 16, "bold"),
            bg="#d1e7ff"
        ).pack(pady=20)

        tk.Label(
            splash,
            text="Developed by Faruk Ahmed\n\nDate: Jan/2025",
            font=("Helvetica", 12),
            bg="#d1e7ff"
        ).pack(pady=10)

        tk.Label(
            splash,
            text="GitHub: https://github.com/bornaly\n\nEmail: bornaly@gmail.com",
            font=("Helvetica", 10),
            bg="#d1e7ff",
            justify="center"
        ).pack(pady=10)

        # Schedule the splash screen to close after 15 seconds and show the main application
        self.root.after(2000, lambda: self.transition_to_main_app(splash))

    def transition_to_main_app(self, splash):
        """
        Close the splash screen and set up the main application.
        """
        splash.destroy()  # Close the splash screen
        #self.setup_main_ui()  # Set up the main application interface
        #self.authenticate_admin()

    def setup_sender_email(self):
        """
        Set up a window for the user to input sender email credentials.
        Includes an additional field for Receiver Email to update ADMIN_EMAIL.
        """

        def save_email():
            email = email_entry.get().strip()
            password = password_entry.get().strip()
            receiver_email = receiver_email_entry.get().strip()

            if not email or not password or not receiver_email:
                messagebox.showerror("Error", "All fields are required!")
                return

            try:
                # Save sender credentials
                SupplementClass.save_sender_credentials(email, password)

                # Save admin email
                SupplementClass.save_admin_email(receiver_email)

                messagebox.showinfo("Success", "Sender and Receiver emails saved successfully!", parent=self.root)
                sender_window.destroy()
                self.setup_admin_credentials()  # Proceed to admin setup

            except Exception as e:
                logging.error(f"Failed to save credentials: {e}")
                messagebox.showerror("Error", f"Failed to save credentials: {e}")

        def show_gmail_guide():
            """Show Gmail App Password setup guide."""
            guide_window = tk.Toplevel(self.root)
            guide_window.title("How to Setup Gmail App Password")
            guide_window.geometry("500x300")
            guide_window.configure(bg="#d1e7ff")

            steps = [
                "1. Go to your Google Account.",
                "2. On the left navigation panel, choose 'Security'.",
                "3. Under 'Signing in to Google', select 'App passwords'.",
                "4. At the bottom, choose 'Select app' and select the app you're using.",
                "5. Choose 'Select device' and select the device you're using.",
                "6. Click 'Generate' to create a 16-character App Password."
            ]

            tk.Label(guide_window, text="Follow these steps:", font=("Helvetica", 12, "bold"), bg="#d1e7ff").pack(
                pady=10)
            for step in steps:
                tk.Label(guide_window, text=step, font=("Helvetica", 12), bg="#d1e7ff", anchor="w").pack(anchor="w",
                                                                                                         padx=20)

            link_label = tk.Label(
                guide_window, text="Open Gmail App Password Page", font=("Helvetica", 12, "underline"), fg="blue",
                bg="#d1e7ff", cursor="hand2"
            )
            link_label.pack(pady=10)
            link_label.bind("<Button-1>", lambda e: webbrowser.open("https://myaccount.google.com/apppasswords", new=1))

            ttk.Button(guide_window, text="Close", command=guide_window.destroy).pack(pady=20)

            guide_window.transient(self.root)
            guide_window.grab_set()
            guide_window.focus_force()

        # Create the sender email setup window
        sender_window = tk.Toplevel(self.root)
        sender_window.title("Setup Sender Email")
        sender_window.configure(bg="#d1e7ff")
        sender_window.resizable(False, False)

        # Center the window relative to Password Manager
        sender_width = 400
        sender_height = 400
        root_x = self.root.winfo_x()
        root_y = self.root.winfo_y()
        root_width = self.root.winfo_width()
        root_height = self.root.winfo_height()

        sender_x = root_x + (root_width // 2) - (sender_width // 2)
        sender_y = root_y + (root_height // 2) - (sender_height // 2)
        sender_window.geometry(f"{sender_width}x{sender_height}+{sender_x}+{sender_y}")

        sender_window.transient(self.root)
        sender_window.grab_set()
        sender_window.focus_force()

        # Sender Email Field
        tk.Label(sender_window, text="Sender Email:", font=("Helvetica", 12), bg="#d1e7ff").pack(pady=10)
        email_entry = ttk.Entry(sender_window, width=30)
        email_entry.pack(pady=5)

        # Gmail App Password Field
        tk.Label(sender_window, text="** Gmail App Password:", font=("Helvetica", 12), bg="#d1e7ff").pack(pady=10)
        password_entry = ttk.Entry(sender_window, width=30, show="*")
        password_entry.pack(pady=5)

        # Sample Password Example
        tk.Label(
            sender_window,
            text="* Example: qwer trew rtyu qsde",
            font=("Helvetica", 10, "italic"),
            fg="gray",
            bg="#d1e7ff",
        ).pack(pady=5)

        # Receiver Email Field
        tk.Label(sender_window, text="Receiver Email:", font=("Helvetica", 12), bg="#d1e7ff").pack(pady=10)
        receiver_email_entry = ttk.Entry(sender_window, width=30)
        receiver_email_entry.pack(pady=5)

        # Gmail Setup Guide Link
        link_label = tk.Label(
            sender_window, text="** How to setup Gmail App password?", font=("Helvetica", 12, "underline"), fg="blue",
            bg="#d1e7ff", cursor="hand2"
        )
        link_label.pack(pady=5)
        link_label.bind("<Button-1>", lambda e: show_gmail_guide())

        # Save Button
        save_button = ttk.Button(sender_window, text="Save Email", command=save_email)
        save_button.pack(pady=20)
        sender_window.bind("<Return>", lambda event: save_button.invoke())
        save_button.focus_set()

    def authenticate_admin(self):
        """
        Authenticate the admin user at the start of the application.
        Ensures that the Password Manager window is properly shown after successful authentication.
        """

        def validate_admin():
            """
            Validate the admin credentials entered by the user.
            If valid, destroy the Admin Login window and launch the Password Manager.
            """
            admin_id = admin_id_entry.get().strip()
            admin_password = admin_password_entry.get().strip()

            try:
                # Validate admin credentials from the database
                conn = sqlite3.connect(SupplementClass.DB_NAME)
                cursor = conn.cursor()
                cursor.execute("SELECT encrypted_password FROM admin WHERE admin_id = ?", (admin_id,))
                result = cursor.fetchone()
                conn.close()

                if result and SupplementClass.decrypt_data(result[0]) == admin_password:
                    messagebox.showinfo("Success", "Admin authenticated successfully!",parent=self.root)  # Centered messagebox
                    login_window.destroy()


                    # Bring the Password Manager window to the top
                    self.root.lift()
                    self.root.attributes("-topmost", True)
                    self.root.attributes("-topmost", False)
                    self.setup_main_ui()
                else:
                    messagebox.showerror("Error", "Invalid Admin Credentials!")
            except Exception as e:
                logging.error(f"Admin authentication failed: {e}")
                messagebox.showerror("Error", f"Authentication failed: {e}")

        # Create the login window
        login_window = tk.Toplevel(self.root)
        login_window.title("Admin Login")
        login_window.geometry("400x250")
        login_window.configure(bg="#d1e7ff")

        # Ensure the login window is focused and on top
        login_window.transient(self.root)
        login_window.grab_set()
        login_window.focus_force()
        login_window.attributes("-topmost", True)
        login_window.attributes("-topmost", False)

        # Center the login window relative to the Password Manager window
        self.center_window(login_window, width=400, height=250)

        # Admin ID Entry
        tk.Label(login_window, text="Logon as Admin ID:", font=("Helvetica", 12), bg="#d1e7ff").pack(pady=10)
        admin_id_entry = ttk.Entry(login_window, width=30)
        admin_id_entry.pack(pady=5)

        # Admin Password Entry
        tk.Label(login_window, text="Logon as Admin Password:", font=("Helvetica", 12), bg="#d1e7ff").pack(pady=10)
        admin_password_entry = ttk.Entry(login_window, width=30, show="*")
        admin_password_entry.pack(pady=5)

        # Login Button
        ttk.Button(login_window, text="Login", command=validate_admin).pack(pady=20)

        # Bind the Enter key to the login function
        login_window.bind("<Return>", lambda event: validate_admin())

    def setup_main_ui(self):
        """
        Set up the main application interface, including CRUD and menus.
        """
        logging.debug("Setting up the main UI.")  # Debug statement

        try:
            # Title Section
            title_frame = tk.Frame(self.root, bg="#4682B4")
            title_frame.pack(fill="x", pady=(10, 20))
            logging.debug("Title frame initialized.")  # Debug statement

            # Load the icon
            try:
                icon_image = Image.open("safe_icon.ico")  # Load the .ico file
                icon_image = icon_image.resize((32, 32))  # Resize the icon to fit
                icon_photo = ImageTk.PhotoImage(icon_image)  # Convert to PhotoImage
            except Exception as e:
                logging.error(f"Unable to load icon: {e}")
                icon_photo = None

            # Grid to center the title and icon
            title_frame.columnconfigure(0, weight=1)
            title_frame.columnconfigure(1, weight=1)
            title_frame.columnconfigure(2, weight=1)

            if icon_photo:
                icon_label = tk.Label(title_frame, image=icon_photo, bg="#4682B4")  # Add the icon to a label
                icon_label.image = icon_photo  # Keep a reference to avoid garbage collection
                icon_label.grid(row=0, column=0, padx=10, pady=10, sticky="e")  # Position icon on the left
                logging.debug("Icon label added.")  # Debug statement

            title_label = tk.Label(
                title_frame,
                text="My Password Manager",
                font=("Helvetica", 18, "bold"),
                bg="#4682B4",
                fg="white"
            )
            title_label.grid(row=0, column=1, padx=10, pady=10, sticky="w")  # Position title in the center
            logging.debug("Title label added.")  # Debug statement

            # CRUD Section (Table and Buttons)
            self.setup_password_crud()
            logging.debug("Password CRUD section initialized.")  # Debug statement

            # Menus
            self.setup_menus()
            logging.debug("Menus set up successfully.")  # Debug statement

            # Force refresh the root window
            self.root.update()
            logging.debug("Main UI setup completed and root window updated.")  # Debug statement

        except Exception as e:
            logging.error(f"Error during setup_main_ui: {e}")
            messagebox.showerror("Error", f"Failed to set up the main UI: {e}")

    def show_upload_summary(self, uploaded_records):
        """
        Display a summary window for the uploaded data during a Complete Override operation.

        Args:
            uploaded_records (list): List of tuples containing the uploaded records (Account ID, Password, Target Name).
        """
        summary_window = tk.Toplevel(self.root)
        summary_window.title("Upload Summary")
        summary_window.geometry("600x700")
        summary_window.configure(bg="#e6f7ff")

        # Close button at the top-right
        def close_summary_window():
            summary_window.destroy()
            self.refresh_table()  # Refresh the grid after closing the summary window

        close_button = ttk.Button(summary_window, text="Close", command=close_summary_window)
        close_button.pack(anchor="ne", padx=10, pady=10)

        tk.Label(summary_window, text="Upload Summary", font=("Helvetica", 14, "bold"),
                 bg="#e6f7ff").pack(pady=10)

        # Frame for uploaded records
        records_frame = tk.Frame(summary_window, bg="#e6f7ff")
        records_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        tk.Label(records_frame, text=f"Uploaded Records ({len(uploaded_records)})", font=("Helvetica", 12, "bold"),
                 bg="#4682B4", fg="white").grid(row=0, column=0, columnspan=3, sticky="nsew", pady=5)

        # Headers for uploaded records
        tk.Label(records_frame, text="Account ID", font=("Helvetica", 12, "bold"), bg="#4682B4", fg="white",
                 width=20).grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        tk.Label(records_frame, text="Password", font=("Helvetica", 12, "bold"), bg="#4682B4", fg="white",
                 width=20).grid(row=1, column=1, padx=5, pady=5, sticky="nsew")
        tk.Label(records_frame, text="Target Name", font=("Helvetica", 12, "bold"), bg="#4682B4", fg="white",
                 width=20).grid(row=1, column=2, padx=5, pady=5, sticky="nsew")

        # Display uploaded records
        if uploaded_records:
            for idx, record in enumerate(uploaded_records, start=2):
                bg_color = "#F0F8FF" if idx % 2 == 0 else "#E6E6FA"
                tk.Label(records_frame, text=record[0], font=("Helvetica", 12), bg=bg_color, width=20,
                         anchor="center").grid(row=idx, column=0, padx=5, pady=5, sticky="nsew")
                tk.Label(records_frame, text=record[1], font=("Helvetica", 12), bg=bg_color, width=20,
                         anchor="center").grid(row=idx, column=1, padx=5, pady=5, sticky="nsew")
                tk.Label(records_frame, text=record[2], font=("Helvetica", 12), bg=bg_color, width=20,
                         anchor="center").grid(row=idx, column=2, padx=5, pady=5, sticky="nsew")
        else:
            tk.Label(records_frame, text="No records were uploaded.", bg="#e6f7ff",
                     font=("Helvetica", 12, "italic")).grid(row=2, column=0, columnspan=3, pady=5)

        # Call refresh_table when the window is closed via the "X" button
        summary_window.protocol("WM_DELETE_WINDOW", close_summary_window)

    def show_preview_and_confirm(self, df, mode):
        """
        Display a preview of the data and confirm the action.
        Args:
            df (pd.DataFrame): The data to preview.
            mode (str): The mode of upload ('override' or 'append').
        """
        preview_window = tk.Toplevel(self.root)
        preview_window.title("Data Preview")
        preview_window.geometry("800x600")
        preview_window.configure(bg="#e6f7ff")

        # Center the preview window on the Password Manager window
        self.center_window(preview_window, width=800, height=600)
        preview_window.transient(self.root)  # Make it a child of the main window
        preview_window.grab_set()  # Prevent interaction with the parent window
        preview_window.focus_force()  # Ensure the window gets focus

        tk.Label(preview_window, text=f"Preview of Uploaded Data ({mode.capitalize()})",
                 font=("Helvetica", 14, "bold"), bg="#e6f7ff").pack(pady=10)

        frame = tk.Frame(preview_window, bg="#e6f7ff")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        canvas = tk.Canvas(frame, bg="#e6f7ff")
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        inner_frame = tk.Frame(canvas, bg="#e6f7ff")
        canvas.create_window((0, 0), window=inner_frame, anchor="nw")
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Populate preview data
        for col_idx, col_name in enumerate(df.columns):
            tk.Label(inner_frame, text=col_name, font=("Helvetica", 12, "bold"), bg="#4682B4", fg="white",
                     width=20).grid(row=0, column=col_idx, padx=5, pady=5, sticky="nsew")

        for row_idx, row_data in enumerate(df.values):
            for col_idx, cell_value in enumerate(row_data):
                bg_color = "#F0F8FF" if row_idx % 2 == 0 else "#E6E6FA"
                tk.Label(inner_frame, text=str(cell_value), font=("Helvetica", 12), bg=bg_color, width=20).grid(
                    row=row_idx + 1, column=col_idx, padx=5, pady=5, sticky="nsew"
                )

        button_frame = tk.Frame(preview_window, bg="#e6f7ff")
        button_frame.pack(pady=10)

        def confirm_upload():
            if mode == "override":
                self.override_data(df)
            elif mode == "append":
                self.append_new_data(df)
            preview_window.destroy()

        def cancel_upload():
            messagebox.showinfo("Cancelled", "Upload has been cancelled. No changes were made.")
            preview_window.destroy()

        ttk.Button(button_frame, text="Upload", command=confirm_upload).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Cancel", command=cancel_upload).pack(side=tk.LEFT, padx=10)

        inner_frame.update_idletasks()
        canvas.configure(scrollregion=canvas.bbox("all"))

    def override_data(self, df):
        """
        Replace all existing data in the database with the new data from the uploaded file.

        Args:
            df (pd.DataFrame): The new data to override existing data in the database.
        """
        try:
            conn = sqlite3.connect(SupplementClass.DB_NAME)
            cursor = conn.cursor()

            # Clear existing data
            cursor.execute("DELETE FROM passwords")
            conn.commit()

            # Insert new data
            records = []
            for _, row in df.iterrows():
                hashed_password = bcrypt.hashpw(row["Password"].encode(), bcrypt.gensalt()).decode()
                cursor.execute(
                    "INSERT INTO passwords (account_id, hashed_password, original_password, target_name) VALUES (?, ?, ?, ?)",
                    (row["Account ID"], hashed_password, row["Password"], row["Target Name"])
                )
                records.append((row["Account ID"], row["Password"], row["Target Name"]))

            conn.commit()
            conn.close()

            # Notify the user and refresh the table
            messagebox.showinfo("Success", f"Upload completed. {len(records)} record(s) updated.")
            self.refresh_table()

        except Exception as e:
            logging.error(f"Failed to override data: {e}")
            messagebox.showerror("Error", "Failed to override data. Please check the logs.")



    def append_new_data(self, df):
        """
        Append only new data to the database.
        Args:
            df (pd.DataFrame): DataFrame containing new records to append.
        """
        try:
            conn = sqlite3.connect(SupplementClass.DB_NAME)
            cursor = conn.cursor()

            # Fetch existing records for comparison
            existing_records = cursor.execute(
                "SELECT account_id, target_name FROM passwords"
            ).fetchall()
            existing_set = set((row[0], row[1]) for row in existing_records)

            # Filter new records
            new_records = df[
                ~df.apply(lambda row: (row["Account ID"], row["Target Name"]) in existing_set, axis=1)
            ]

            if new_records.empty:
                messagebox.showinfo("No New Data", "All records already exist in the database.")
                return

            # Insert new records into the database
            for _, row in new_records.iterrows():
                hashed_password = bcrypt.hashpw(row["Password"].encode(), bcrypt.gensalt())
                cursor.execute(
                    "INSERT INTO passwords (account_id, hashed_password, original_password, target_name) VALUES (?, ?, ?, ?)",
                    (row["Account ID"], hashed_password.decode(), row["Password"], row["Target Name"])
                )

            conn.commit()
            conn.close()

            # Notify user
            messagebox.showinfo("Success", f"Upload completed. {len(new_records)} new record(s) added.")
            self.refresh_table()  # Refresh the table to show new data

        except Exception as e:
            logging.error(f"Failed to append data: {e}")
            messagebox.showerror("Error", "Failed to append new data.")


    def process_uploaded_data(self, df, mode):
        """
        Processes uploaded data based on the selected mode ('override' or 'append').
        Includes a preview window for confirmation.
        """
        if mode == "override":
            # Call the preview window to confirm the override
            self.show_preview_and_confirm(df, mode)
        elif mode == "append":
            # Identify new records to append
            conn = sqlite3.connect(SupplementClass.DB_NAME)
            cursor = conn.cursor()

            # Get all existing records
            existing_records = cursor.execute(
                "SELECT account_id, target_name FROM passwords"
            ).fetchall()

            # Create a set for quick lookup
            existing_set = set((row[0], row[1]) for row in existing_records)

            # Filter new records
            new_records = df[
                ~df.apply(lambda row: (row["Account ID"], row["Target Name"]) in existing_set, axis=1)
            ]

            conn.close()

            if not new_records.empty:
                # Call the preview window to confirm the append
                self.show_preview_and_confirm(new_records, mode)
            else:
                messagebox.showinfo("No New Data", "No new records to append. All data already exists in the database.")

    def handle_conflicts(self, conflicts, conn, cursor):
        """
        Show a form to resolve conflicts by allowing the user to select desired records.
        Includes a Resolve Conflicts button for processing.
        """
        conflict_window = tk.Toplevel(self.root)
        conflict_window.title("Resolve Conflicts")
        conflict_window.geometry("800x600")
        conflict_window.configure(bg="#e6f7ff")

        # Frame for the conflicts table
        frame = tk.Frame(conflict_window, bg="#e6f7ff")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Canvas for scrolling
        canvas = tk.Canvas(frame, bg="#e6f7ff")
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scrollbar for the canvas
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Link scrollbar to canvas
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        # Inner frame for the grid
        inner_frame = tk.Frame(canvas, bg="#e6f7ff")
        canvas.create_window((0, 0), window=inner_frame, anchor="nw")

        # List to hold checkbox states
        check_vars = []

        # Header row
        header_bg = "#4682B4"
        header_fg = "white"
        tk.Label(inner_frame, text="Select", bg=header_bg, fg=header_fg, font=("Helvetica", 12, "bold"), width=10).grid(
            row=0, column=0, padx=5, pady=5)
        tk.Label(inner_frame, text="Account ID", bg=header_bg, fg=header_fg, font=("Helvetica", 12, "bold"),
                 width=20).grid(row=0, column=1, padx=5, pady=5)
        tk.Label(inner_frame, text="Target Name", bg=header_bg, fg=header_fg, font=("Helvetica", 12, "bold"),
                 width=20).grid(row=0, column=2, padx=5, pady=5)
        tk.Label(inner_frame, text="Password", bg=header_bg, fg=header_fg, font=("Helvetica", 12, "bold"),
                 width=20).grid(row=0, column=3, padx=5, pady=5)

        # Add conflicts as rows with checkboxes
        for index, conflict in enumerate(conflicts, start=1):
            bg_color = "#F0F8FF" if index % 2 == 0 else "#E6E6FA"

            # Checkbox for selection
            check_var = tk.BooleanVar(value=True)  # Checked by default
            check_vars.append(check_var)
            chk = ttk.Checkbutton(inner_frame, variable=check_var)
            chk.grid(row=index, column=0, padx=5, pady=5, sticky="w")

            # Data columns
            tk.Label(inner_frame, text=conflict[0], bg=bg_color, font=("Helvetica", 12), width=20).grid(row=index,
                                                                                                        column=1,
                                                                                                        padx=5, pady=5,
                                                                                                        sticky="w")
            tk.Label(inner_frame, text=conflict[1], bg=bg_color, font=("Helvetica", 12), width=20).grid(row=index,
                                                                                                        column=2,
                                                                                                        padx=5, pady=5,
                                                                                                        sticky="w")
            tk.Label(inner_frame, text=conflict[2], bg=bg_color, font=("Helvetica", 12), width=20).grid(row=index,
                                                                                                        column=3,
                                                                                                        padx=5, pady=5,
                                                                                                        sticky="w")

        def refresh_grid(table, conn):
            """
            Refresh the grid to ensure it displays the current data from the database.
            Args:
                table (ttk.Treeview): The grid widget to update.
                conn (sqlite3.Connection): The database connection.
            """
            for row in table.get_children():
                table.delete(row)

            cursor = conn.cursor()
            cursor.execute("SELECT account_id, original_password, target_name FROM passwords ORDER BY id DESC")
            rows = cursor.fetchall()

            for index, row in enumerate(rows):
                bg_color = "#F0F8FF" if index % 2 == 0 else "#E6E6FA"
                table.insert("", "end", values=row, tags=("oddrow" if index % 2 == 0 else "evenrow"))

            table.tag_configure("oddrow", background="#F0F8FF")
            table.tag_configure("evenrow", background="#E6E6FA")


        # Resolve Conflicts Button
        def resolve_conflicts():
            """
            Process selected records to resolve conflicts.
            Classifies records as updated or denied and displays a summary.
            """
            updated_records = []
            denied_records = []

            for index, conflict in enumerate(conflicts):
                if check_vars[index].get():  # Process only checked rows
                    account_id, target_name, password = conflict

                    # Check if the record exists in the database
                    cursor.execute(
                        "SELECT original_password FROM passwords WHERE account_id = ? AND target_name = ?",
                        (account_id, target_name)
                    )
                    result = cursor.fetchone()

                    if result:
                        # Compare unhashed passwords
                        stored_password = result[0]
                        if stored_password == password:
                            # Record already exists, add to denied
                            denied_records.append(conflict)
                            continue

                    # Insert or update the record
                    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                    cursor.execute(
                        "INSERT OR REPLACE INTO passwords (account_id, hashed_password, original_password, target_name) VALUES (?, ?, ?, ?)",
                        (account_id, hashed_password.decode(), password, target_name)
                    )
                    updated_records.append(conflict)

            # Commit changes and close the connection
            conn.commit()
            conn.close()

            # Display the summary
            show_summary(updated_records, denied_records)
            conflict_window.destroy()

        # Add the Resolve Conflicts button
        button_frame = tk.Frame(conflict_window, bg="#e6f7ff")
        button_frame.pack(fill=tk.X, pady=10)

        resolve_button = ttk.Button(button_frame, text="Resolve Conflicts", command=resolve_conflicts)
        resolve_button.pack(side=tk.RIGHT, padx=10)

        conflict_window.transient(self.root)
        conflict_window.grab_set()
        conflict_window.focus_force()

        def show_summary(updated_records, denied_records):
            """
            Display a summary window showing records that were updated and denied.
            Includes center-aligned columns and a Close button on the top-right.
            """
            summary_window = tk.Toplevel(self.root)
            summary_window.title("Conflict Resolution Summary")
            summary_window.geometry("800x600")
            summary_window.configure(bg="#e6f7ff")

            # Close button at the top-right
            close_button = ttk.Button(summary_window, text="Close", command=summary_window.destroy)
            close_button.pack(anchor="ne", padx=10, pady=10)

            tk.Label(summary_window, text="Conflict Resolution Summary", font=("Helvetica", 14, "bold"),
                     bg="#e6f7ff").pack(pady=10)

            # Updated Records Section
            updated_frame = tk.Frame(summary_window, bg="#e6f7ff")
            updated_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            tk.Label(updated_frame, text=f"Updated Records ({len(updated_records)})", font=("Helvetica", 12, "bold"),
                     bg="#4682B4", fg="white").grid(row=0, column=0, columnspan=3, sticky="nsew", pady=5)

            # Headers for updated records
            tk.Label(updated_frame, text="Account ID", font=("Helvetica", 12, "bold"), bg="#4682B4", fg="white",
                     width=20).grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
            tk.Label(updated_frame, text="Password", font=("Helvetica", 12, "bold"), bg="#4682B4", fg="white",
                     width=20).grid(row=1, column=1, padx=5, pady=5, sticky="nsew")
            tk.Label(updated_frame, text="Target Name", font=("Helvetica", 12, "bold"), bg="#4682B4", fg="white",
                     width=20).grid(row=1, column=2, padx=5, pady=5, sticky="nsew")

            if updated_records:
                for idx, record in enumerate(updated_records, start=2):
                    bg_color = "#F0F8FF" if idx % 2 == 0 else "#E6E6FA"
                    tk.Label(updated_frame, text=record[0], font=("Helvetica", 12), bg=bg_color, width=20,
                             anchor="center").grid(row=idx, column=0, padx=5, pady=5, sticky="nsew")
                    tk.Label(updated_frame, text=record[2], font=("Helvetica", 12), bg=bg_color, width=20,
                             anchor="center").grid(row=idx, column=1, padx=5, pady=5, sticky="nsew")
                    tk.Label(updated_frame, text=record[1], font=("Helvetica", 12), bg=bg_color, width=20,
                             anchor="center").grid(row=idx, column=2, padx=5, pady=5, sticky="nsew")
            else:
                tk.Label(updated_frame, text="No records were updated.", bg="#e6f7ff",
                         font=("Helvetica", 12, "italic")).grid(row=2, column=0, columnspan=3, pady=5)

            # Denied Records Section
            denied_frame = tk.Frame(summary_window, bg="#e6f7ff")
            denied_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            tk.Label(denied_frame, text=f"Denied Records (Already Exist) ({len(denied_records)})",
                     font=("Helvetica", 12, "bold"),
                     bg="#4682B4", fg="white").grid(row=0, column=0, columnspan=3, sticky="nsew", pady=5)

            # Headers for denied records
            tk.Label(denied_frame, text="Account ID", font=("Helvetica", 12, "bold"), bg="#4682B4", fg="white",
                     width=20).grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
            tk.Label(denied_frame, text="Password", font=("Helvetica", 12, "bold"), bg="#4682B4", fg="white",
                     width=20).grid(row=1, column=1, padx=5, pady=5, sticky="nsew")
            tk.Label(denied_frame, text="Target Name", font=("Helvetica", 12, "bold"), bg="#4682B4", fg="white",
                     width=20).grid(row=1, column=2, padx=5, pady=5, sticky="nsew")

            if denied_records:
                for idx, record in enumerate(denied_records, start=2):
                    bg_color = "#FFE4E1" if idx % 2 == 0 else "#FFCCCC"
                    tk.Label(denied_frame, text=record[0], font=("Helvetica", 12), bg=bg_color, width=20,
                             anchor="center").grid(row=idx, column=0, padx=5, pady=5, sticky="nsew")
                    tk.Label(denied_frame, text=record[2], font=("Helvetica", 12), bg=bg_color, width=20,
                             anchor="center").grid(row=idx, column=1, padx=5, pady=5, sticky="nsew")
                    tk.Label(denied_frame, text=record[1], font=("Helvetica", 12), bg=bg_color, width=20,
                             anchor="center").grid(row=idx, column=2, padx=5, pady=5, sticky="nsew")
            else:
                tk.Label(denied_frame, text="No records were denied.", bg="#e6f7ff",
                         font=("Helvetica", 12, "italic")).grid(row=2, column=0, columnspan=3, pady=5)

    def upload_data(self):
        """
        Opens a file dialog to upload data and processes it based on user selection.
        """
        file_path = filedialog.askopenfilename(
            title="Select Data File",
            filetypes=[("Excel Files", "*.xlsx"), ("CSV Files", "*.csv")]
        )

        if not file_path:
            return  # User canceled the dialog

        try:
            # Read the file into a DataFrame
            if file_path.endswith(".xlsx"):
                df = pd.read_excel(file_path)
            elif file_path.endswith(".csv"):
                df = pd.read_csv(file_path)
            else:
                messagebox.showerror("Error", "Unsupported file format!")
                return
        except Exception as e:
            logging.error(f"Error reading file: {e}")
            messagebox.showerror("Error", f"Failed to read file: {e}")
            return

        # Validate columns
        required_columns = {"Account ID", "Password", "Target Name"}
        if not required_columns.issubset(df.columns):
            messagebox.showerror("Error", "The file must contain 'Account ID', 'Password', and 'Target Name' columns.")
            return

        # Show options to user
        def process_selection(mode):
            self.process_uploaded_data(df, mode)
            selection_window.destroy()

        selection_window = tk.Toplevel(self.root)
        selection_window.title("Data Upload Mode")
        selection_window.geometry("400x200")
        selection_window.configure(bg="#d1e7ff")

        tk.Label(selection_window, text="Choose Upload Mode:", font=("Helvetica", 14), bg="#d1e7ff").pack(pady=20)
        ttk.Button(selection_window, text="Complete Override", command=lambda: process_selection("override")).pack(
            pady=10)
        ttk.Button(selection_window, text="Append New Data", command=lambda: process_selection("append")).pack(pady=10)

        selection_window.transient(self.root)
        selection_window.grab_set()
        selection_window.focus_force()

    def refresh_table(self):
        """
        Refresh the grid to ensure it displays up-to-date data from the database with consistent coloring.
        """
        try:
            # Clear existing rows
            for row in self.table.get_children():
                self.table.delete(row)

            # Fetch latest data from the database
            conn = sqlite3.connect(SupplementClass.DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT account_id, hashed_password, target_name FROM passwords ORDER BY id DESC")
            rows = cursor.fetchall()
            conn.close()

            # Populate the grid with new data
            for index, row in enumerate(rows):
                bg_color = "#F0F8FF" if index % 2 == 0 else "#E6E6FA"
                self.table.insert("", "end", values=row, tags=("oddrow" if index % 2 == 0 else "evenrow"))

            # Update row styles and total count
            self.table.tag_configure("oddrow", background="#F0F8FF")
            self.table.tag_configure("evenrow", background="#E6E6FA")
            self.total_records_label.config(text=f"Total Records: {len(rows)}")

            logging.debug(f"Refreshed table with {len(rows)} records.")
        except Exception as e:
            logging.error(f"Error refreshing table: {e}")
            messagebox.showerror("Error", "Failed to refresh the table.")

    def retrieve_password(self):
        """
        Retrieve the original password based on Account ID and Target Name or the selected record in the grid.
        Provides a neatly aligned window with options to expose the password.
        """
        selected_items = self.table.selection()

        if selected_items:
            # If a record is selected, use it for retrieval
            selected_item = selected_items[0]
            values = self.table.item(selected_item, "values")
            account_id, hashed_password, target_name = values
        else:
            # Otherwise, get inputs from the entry fields
            account_id = self.account_id_entry.get().strip()
            target_name = self.target_entry.get().strip()

            if not account_id or not target_name:
                messagebox.showerror("Error", "Account ID and Target Name are required!")
                return

        try:
            conn = sqlite3.connect(SupplementClass.DB_NAME)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT original_password FROM passwords WHERE account_id = ? AND target_name = ?",
                (account_id, target_name)
            )
            result = cursor.fetchone()
            conn.close()

            if result:
                original_password = result[0]

                # Create the password retrieval window
                retrieve_window = tk.Toplevel(self.root)
                retrieve_window.title("Retrieve Password")
                retrieve_window.geometry("600x300")  # Adjusted width
                self.center_window(retrieve_window)  # Center it on the main window
                retrieve_window.configure(bg="#e6f7ff")

                # Account ID
                tk.Label(retrieve_window, text="Account ID:", font=("Helvetica", 12), bg="#e6f7ff", anchor="w").grid(
                    row=0, column=0, padx=10, pady=10, sticky="w"
                )
                tk.Label(retrieve_window, text=account_id, font=("Helvetica", 10), bg="#F0F8FF", width=30,
                         anchor="w").grid(
                    row=0, column=1, padx=10, pady=10, sticky="w"
                )

                # Hashed Password
                tk.Label(retrieve_window, text="Hashed Password:", font=("Helvetica", 12), bg="#e6f7ff",
                         anchor="w").grid(
                    row=1, column=0, padx=10, pady=10, sticky="w"
                )
                tk.Label(retrieve_window, text=hashed_password, font=("Helvetica", 12), bg="#F0F8FF", width=30,
                         anchor="w").grid(
                    row=1, column=1, padx=10, pady=10, sticky="w"
                )

                # Target Name
                tk.Label(retrieve_window, text="Target Name:", font=("Helvetica", 12), bg="#e6f7ff", anchor="w").grid(
                    row=2, column=0, padx=10, pady=10, sticky="w"
                )
                tk.Label(retrieve_window, text=target_name, font=("Helvetica", 12), bg="#F0F8FF", width=30,
                         anchor="w").grid(
                    row=2, column=1, padx=10, pady=10, sticky="w"
                )

                # Password
                tk.Label(retrieve_window, text="Password:", font=("Helvetica", 12), bg="#e6f7ff", anchor="w").grid(
                    row=3, column=0, padx=10, pady=10, sticky="w"
                )
                password_label = tk.Label(retrieve_window, text="********", font=("Helvetica", 12), bg="yellow",
                                          width=30, anchor="w")
                password_label.grid(row=3, column=1, padx=10, pady=10, sticky="w")

                def expose_password():
                    """Unhash and display the original password."""
                    expose_button.config(state="disabled")  # Disable the button after exposing
                    password_label.config(text=original_password)

                # Expose Button
                expose_button = tk.Button(
                    retrieve_window,
                    text="Expose",
                    command=expose_password,
                    bg="green",
                    fg="white",
                    font=("Helvetica", 12, "bold"),
                    relief="raised",
                    bd=2
                )
                expose_button.grid(row=3, column=2, padx=10, pady=10)

                def close_window():
                    """Close the retrieve window and clear the fields in the main interface."""
                    retrieve_window.destroy()
                    # Clear the fields in the main Password Manager window
                    self.account_id_entry.delete(0, tk.END)
                    self.password_entry.delete(0, tk.END)
                    self.target_entry.delete(0, tk.END)

                # Close Button
                ttk.Button(retrieve_window, text="Close", command=close_window).grid(
                    row=4, column=0, columnspan=3, pady=20, sticky="n"
                )
            else:
                messagebox.showerror("Error", "No matching record found!")

        except Exception as e:
            logging.error(f"Error retrieving password: {e}")
            messagebox.showerror("Error", "An error occurred while retrieving the password. Check logs for details.")

    def edit_selected(self):
        """
        Open a new window to edit the selected record from the grid.
        Allows modification of the account ID, password, and target name fields.
        Includes a Cancel button with confirmation.
        """
        selected_items = self.table.selection()
        if len(selected_items) != 1:
            messagebox.showerror("Error", "Please select exactly one row to edit!")
            return

        selected_item = self.table.selection()[0]
        values = self.table.item(selected_item, "values")
        old_account_id, hashed_password, target_name = values

        # Fetch original password from the database
        conn = sqlite3.connect(SupplementClass.DB_NAME)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT original_password FROM passwords WHERE account_id = ? AND target_name = ?",
            (old_account_id, target_name),
        )
        result = cursor.fetchone()
        conn.close()

        if not result:
            messagebox.showerror("Error", "No matching record found in the database!")
            return

        original_password = result[0]

        # Open edit window
        edit_window = tk.Toplevel(self.root)
        edit_window.title("Edit Password")
        edit_window.geometry("400x300")
        edit_window.configure(bg="#e6f7ff")
        self.center_window(edit_window)

        # Populate fields
        tk.Label(edit_window, text="Account ID:", font=("Helvetica", 12), bg="#e6f7ff").pack(pady=10)
        account_id_entry = ttk.Entry(edit_window, width=30)
        account_id_entry.insert(0, old_account_id)
        account_id_entry.pack(pady=5)

        tk.Label(edit_window, text="Password:", font=("Helvetica", 12), bg="#e6f7ff").pack(pady=10)
        password_entry = ttk.Entry(edit_window, width=30)
        password_entry.insert(0, original_password)
        password_entry.pack(pady=5)

        tk.Label(edit_window, text="Target Name:", font=("Helvetica", 12), bg="#e6f7ff").pack(pady=10)
        target_entry = ttk.Entry(edit_window, width=30)
        target_entry.insert(0, target_name)
        target_entry.pack(pady=5)

        def save_changes():
            """
            Save changes made in the edit window to the database and refresh the table.
            """
            new_account_id = account_id_entry.get().strip()
            new_password = password_entry.get().strip()
            new_target_name = target_entry.get().strip()

            if not new_account_id or not new_password or not new_target_name:
                messagebox.showerror("Error", "All fields are required!")
                return

            try:
                conn = sqlite3.connect(SupplementClass.DB_NAME)
                cursor = conn.cursor()

                # Check for duplicate Account ID and Target Name combination
                if new_account_id != old_account_id or new_target_name != target_name:
                    cursor.execute(
                        "SELECT COUNT(*) FROM passwords WHERE account_id = ? AND target_name = ?",
                        (new_account_id, new_target_name),
                    )
                    if cursor.fetchone()[0] > 0:
                        messagebox.showerror("Error", "The new Account ID and Target Name combination already exists!")
                        return

                # Hash the new password
                hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

                # Perform the update
                cursor.execute(
                    """
                    UPDATE passwords 
                    SET account_id = ?, 
                        original_password = ?, 
                        hashed_password = ?, 
                        target_name = ?
                    WHERE account_id = ?
                    """,
                    (new_account_id, new_password, hashed_password, new_target_name, old_account_id),
                )

                conn.commit()
                conn.close()

                # Refresh the table to show updated data
                self.refresh_table()

                # Notify the user and close the edit window
                messagebox.showinfo("Success", f"Record updated successfully for Account ID: {new_account_id}.")
                edit_window.destroy()

            except Exception as e:
                logging.error(f"Error saving changes: {e}")
                messagebox.showerror("Error", "Failed to save changes!")

        def cancel_changes():
            """
            Confirm and close the edit window without saving changes.
            """
            # if messagebox.askyesno("Confirm Cancel", "Are you sure you want to discard changes?"):
            #     edit_window.destroy()
            edit_window.destroy()

        # Add Save and Cancel buttons
        button_frame = tk.Frame(edit_window, bg="#e6f7ff")
        button_frame.pack(pady=20)

        save_button = ttk.Button(button_frame, text="Save", command=save_changes)
        save_button.grid(row=0, column=0, padx=10)

        cancel_button = ttk.Button(button_frame, text="Cancel", command=cancel_changes)
        cancel_button.grid(row=0, column=1, padx=10)


    def delete_selected(self):
        """
        Delete the selected rows from the database after user confirmation.
        Show a message with the number of records deleted or canceled.
        """
        selected_items = self.table.selection()
        if not selected_items:
            messagebox.showerror("Error", "No records selected for deletion!")
            return

        try:
            # Collect selected records for confirmation
            selected_records = []
            for item in selected_items:
                values = self.table.item(item, 'values')
                selected_records.append(values)

            # Format selected records for display in confirmation dialog
            records_message = "\n".join([f"Account ID: {rec[0]}, Target Name: {rec[2]}" for rec in selected_records])

            # Ask for confirmation
            confirm = messagebox.askyesno(
                "Confirm Deletion",
                f"Are you sure you want to delete the following records?\n\n{records_message}"
            )
            if not confirm:
                messagebox.showinfo("Cancelled", f"Deletion cancelled. {len(selected_records)} record(s) not deleted.")
                return

            # Proceed with deletion if confirmed
            deleted_records = []
            conn = sqlite3.connect(SupplementClass.DB_NAME)
            cursor = conn.cursor()

            for record in selected_records:
                account_id, _, target_name = record
                cursor.execute(
                    "DELETE FROM passwords WHERE account_id = ? AND target_name = ?",
                    (account_id, target_name)
                )
                deleted_records.append(record)

            conn.commit()
            conn.close()

            # Refresh the table and notify the user
            self.refresh_table()
            deleted_message = f"{len(deleted_records)} record(s) deleted:\n"
            deleted_message += "\n".join([f"Account ID: {rec[0]}, Target Name: {rec[2]}" for rec in deleted_records])
            messagebox.showinfo("Deleted Records", deleted_message)

        except Exception as e:
            logging.error(f"Failed to delete records: {e}")
            messagebox.showerror("Error", f"Failed to delete records: {e}")

    def copy_selected(self):
        """
        Copy selected rows from the table to the system clipboard.
        """
        selected_items = self.table.selection()

        if not selected_items:
            messagebox.showerror("Error", "No rows selected to copy!")
            return

        try:
            # Collect data from selected rows
            rows = []
            for item in selected_items:
                row = self.table.item(item, "values")
                rows.append("\t".join(row))  # Tab-separated for better formatting

            # Copy data to clipboard
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(rows))
            self.root.update()  # Update the clipboard
            messagebox.showinfo("Success", "Selected rows copied to clipboard!")
        except Exception as e:
            logging.error(f"Failed to copy selected rows: {e}")
            messagebox.showerror("Error", "Failed to copy rows. Check logs for details.")

    def setup_password_crud(self):
        """
        Set up CRUD functionality for managing passwords with a colorful data grid.
        Includes vertical and horizontal scrollbars, a search field,
        and right-click or Ctrl+C to copy rows, with support for mouse drag selection.
        """

        def save_password():
            """
            Save the entered password details into the database and refresh the table.
            """
            account_id = self.account_id_entry.get().strip()
            password = self.password_entry.get().strip()
            target_name = self.target_entry.get().strip()

            if not account_id or not password or not target_name:
                messagebox.showerror("Error", "All fields are required!")
                return

            try:
                conn = sqlite3.connect(SupplementClass.DB_NAME)
                cursor = conn.cursor()

                # Check for duplicates
                cursor.execute(
                    "SELECT COUNT(*) FROM passwords WHERE account_id = ? AND target_name = ?",
                    (account_id, target_name)
                )
                count = cursor.fetchone()[0]

                if count > 0:
                    messagebox.showwarning("Duplicate Entry",
                                           "This Account ID and Target Name combination already exists.")
                    conn.close()
                    return

                # Hash the password and save it to the database
                hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                cursor.execute(
                    "INSERT INTO passwords (account_id, hashed_password, original_password, target_name) VALUES (?, ?, ?, ?)",
                    (account_id, hashed_password.decode(), password, target_name)
                )
                conn.commit()
                conn.close()

                # Clear the input fields
                self.account_id_entry.delete(0, tk.END)
                self.password_entry.delete(0, tk.END)
                self.target_entry.delete(0, tk.END)

                # Refresh the table
                self.refresh_table()

                # Notify the user
                messagebox.showinfo("Success", "Password saved successfully!", parent=self.root)
            except Exception as e:
                logging.error(f"Failed to save password: {e}")
                messagebox.showerror("Error", f"Failed to save password: {e}")

        def filter_table(event):
            """
            Dynamically filter the table based on search input.
            """
            search_text = self.search_entry.get().strip().lower()
            for row in self.table.get_children():
                self.table.delete(row)

            conn = sqlite3.connect(SupplementClass.DB_NAME)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT account_id, hashed_password, target_name FROM passwords WHERE LOWER(account_id) LIKE ? OR LOWER(target_name) LIKE ?",
                (f"%{search_text}%", f"%{search_text}%")
            )
            rows = cursor.fetchall()
            conn.close()

            for index, row in enumerate(rows):
                bg_color = "#F0F8FF" if index % 2 == 0 else "#E6E6FA"
                self.table.insert("", "end", values=row, tags=("oddrow" if index % 2 == 0 else "evenrow"))

            self.table.tag_configure("oddrow", background="#F0F8FF")
            self.table.tag_configure("evenrow", background="#E6E6FA")

        # Input fields
        input_frame = tk.Frame(self.root, bg="#e6f7ff")
        input_frame.pack(pady=10)

        tk.Label(input_frame, text="Account ID:", font=("Helvetica", 12), bg="#e6f7ff").grid(row=0, column=0, padx=15,
                                                                                             pady=10)
        self.account_id_entry = ttk.Entry(input_frame, width=30)
        self.account_id_entry.grid(row=0, column=1, padx=15, pady=10)

        tk.Label(input_frame, text="Password:", font=("Helvetica", 12), bg="#e6f7ff").grid(row=1, column=0, padx=15,
                                                                                           pady=10)
        self.password_entry = ttk.Entry(input_frame, width=30, show="*")
        self.password_entry.grid(row=1, column=1, padx=15, pady=10)

        tk.Label(input_frame, text="Target Name:", font=("Helvetica", 12), bg="#e6f7ff").grid(row=2, column=0, padx=15,
                                                                                              pady=10)
        self.target_entry = ttk.Entry(input_frame, width=30)
        self.target_entry.grid(row=2, column=1, padx=15, pady=10)

        # Buttons
        button_frame = tk.Frame(self.root, bg="#e6f7ff")
        button_frame.pack(pady=10)

        save_button = tk.Button(button_frame, text="Save Password", command=save_password, bg="#4CAF50", fg="white",
                                font=("Helvetica", 12, "bold"))
        save_button.grid(row=0, column=0, padx=10, pady=5)

        retrieve_button = tk.Button(button_frame, text="Retrieve Password", command=self.retrieve_password,
                                    bg="#2196F3", fg="white", font=("Helvetica", 12, "bold"))
        retrieve_button.grid(row=0, column=1, padx=10, pady=5)

        delete_button = tk.Button(button_frame, text="Delete Selected", command=self.delete_selected,
                                  bg="#F44336", fg="white", font=("Helvetica", 12, "bold"))
        delete_button.grid(row=0, column=2, padx=10, pady=5)

        edit_button = tk.Button(button_frame, text="Edit Selected", command=self.edit_selected, bg="#FF9800",
                                fg="white", font=("Helvetica", 12, "bold"))
        edit_button.grid(row=0, column=3, padx=10, pady=5)

        # Search Bar
        search_frame = tk.Frame(self.root, bg="#e6f7ff")
        search_frame.pack(pady=10)

        tk.Label(search_frame, text="Search:", font=("Helvetica", 12), bg="#e6f7ff").grid(row=0, column=0, padx=15,
                                                                                          pady=10)
        self.search_entry = tk.Entry(search_frame, width=30, bg="yellow", fg="blue", font=("Helvetica", 12))
        self.search_entry.grid(row=0, column=1, padx=15, pady=10)
        self.search_entry.bind("<KeyRelease>", filter_table)

        # Configure grid styling
        style = ttk.Style()
        style.configure("Treeview", font=("Helvetica", 12), rowheight=30)
        style.configure("Treeview.Heading", font=("Helvetica", 12, "bold"))

        # Table with scrollbars
        table_frame = tk.Frame(self.root)
        table_frame.pack(pady=10, fill=tk.BOTH, expand=True)

        table_columns = ("Account ID", "Hashed Password", "Target Name")

        v_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL)
        h_scrollbar = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL)

        self.table = ttk.Treeview(
            table_frame,
            columns=table_columns,
            show="headings",
            height=10,
            yscrollcommand=v_scrollbar.set,
            xscrollcommand=h_scrollbar.set,
            selectmode="extended",  # Allow multiple selection
        )
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

        self.table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scrollbar.config(command=self.table.yview)
        h_scrollbar.config(command=self.table.xview)

        for col in table_columns:
            self.table.heading(col, text=col, anchor="center")
            self.table.column(col, width=200, anchor="center")

        # Right-click context menu
        def show_context_menu(event):
            """
            Show the context menu on right-click.
            """
            row_id = self.table.identify_row(event.y)
            if row_id:
                self.table.selection_add(row_id)  # Ensure clicked row is added to selection
            context_menu.post(event.x_root, event.y_root)

        # Copy selected rows to clipboard
        def copy_selected(event=None):
            """
            Copy selected rows from the table to the system clipboard.
            """
            selected_items = self.table.selection()
            if not selected_items:
                messagebox.showerror("Error", "No rows selected to copy!")
                return

            try:
                # Collect data from selected rows
                rows = ["\t".join(self.table.item(item, "values")) for item in selected_items]
                self.root.clipboard_clear()
                self.root.clipboard_append("\n".join(rows))
                self.root.update()  # Update the clipboard
                #messagebox.showinfo("Success", "Selected rows copied to clipboard!")
            except Exception as e:
                logging.error(f"Failed to copy selected rows: {e}")
                messagebox.showerror("Error", "Failed to copy rows. Check logs for details.")

        # Handle drag selection
        def drag_select(event):
            """
            Select rows while dragging the mouse.
            """
            row_id = self.table.identify_row(event.y)
            if row_id:
                self.table.selection_add(row_id)  # Add the row to the current selection

        # Context menu
        context_menu = tk.Menu(self.root, tearoff=0)
        context_menu.add_command(label="Copy", command=copy_selected)

        # Bind right-click, Ctrl+C, and mouse drag
        self.table.bind("<Button-3>", show_context_menu)  # Right-click
        self.root.bind("<Control-c>", copy_selected)  # Ctrl+C
        self.table.bind("<B1-Motion>", drag_select)  # Mouse drag

        # Footer
        footer_frame = tk.Frame(self.root, bg="#e6f7ff")
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self.total_records_label = tk.Label(
            footer_frame, text="Total Records: 0", font=("Helvetica", 12), bg="#e6f7ff", anchor="center"
        )
        self.total_records_label.pack(pady=6)

        self.refresh_table()


    def setup_menus(self):
        """
        Set up the Tool and Maintenance menus.
        """
        menu_bar = Menu(self.root)

        # Tools Menu
        tools_menu = Menu(menu_bar, tearoff=0)
        tools_menu.add_command(label="1. Reset Admin Password", command=SupplementClass.send_recovery_email)
        tools_menu.add_separator()
        tools_menu.add_command(label="2. Exit", command=self.root.destroy)  # Exits the program
        menu_bar.add_cascade(label="Tools", menu=tools_menu)

        # Maintenance Menu
        maintenance_menu = Menu(menu_bar, tearoff=0)
        maintenance_menu.add_command(label="1. Reset Admin", command=self.reset_admin)
        maintenance_menu.add_command(label="2. Reset Email Sender", command=self.reset_email_sender)
        maintenance_menu.add_command(label="3. Export Data to Excel", command=self.export_to_excel)
        maintenance_menu.add_command(label="4. Upload Data", command=self.upload_data)
        menu_bar.add_cascade(label="Maintenance", menu=maintenance_menu)


        # About Menu
        about_menu = Menu(menu_bar, tearoff=0)
        about_menu.add_command(label="1. About Us", command=self.show_about_window)
        menu_bar.add_cascade(label="About", menu=about_menu)

        self.root.config(menu=menu_bar)

    def reset_admin(self):
        """
        Reset the admin password via a popup dialog.
        Allows the user to update only the admin password.
        """

        def save_new_admin_password():
            new_admin_password = admin_password_entry.get().strip()

            if not new_admin_password:
                messagebox.showerror("Error", "Password field cannot be empty!")
                return

            try:
                # Encrypt and save the new admin password
                encrypted_password = SupplementClass.encrypt_data(new_admin_password)

                #conn = sqlite3.connect(DB_NAME)
                conn = sqlite3.connect(SupplementClass.DB_NAME)
                cursor = conn.cursor()
                # Update the admin password for the hardcoded admin_id
                cursor.execute(
                    "UPDATE admin SET encrypted_password = ? WHERE admin_id = ?",
                    (encrypted_password, "admin")
                )
                conn.commit()

                # Check if the password update was successful
                if cursor.rowcount == 0:  # If no rows were updated, insert a new record
                    cursor.execute(
                        "INSERT INTO admin (admin_id, encrypted_password) VALUES (?, ?)",
                        ("admin", encrypted_password)
                    )
                    conn.commit()

                conn.close()
                messagebox.showinfo("Success", "Admin password updated successfully!",parent=self.root) # Centered messagebox
                reset_window.destroy()
            except Exception as e:
                logging.error(f"Error updating admin password: {e}")
                messagebox.showerror("Error", f"Failed to update admin password: {e}")

        # Popup for resetting admin password
        reset_window = tk.Toplevel(self.root)
        reset_window.title("Reset Admin Password")
        reset_window.geometry("400x200")
        reset_window.configure(bg="#d1e7ff")
        reset_window.iconphoto(True, tk.PhotoImage(file=SupplementClass.prepare_icon()))

        tk.Label(reset_window, text="New Admin Password:", font=("Helvetica", 12), bg="#d1e7ff").pack(pady=10)
        admin_password_entry = ttk.Entry(reset_window, width=30, show="*")
        admin_password_entry.pack(pady=10)

        ttk.Button(reset_window, text="Save Password", command=save_new_admin_password).pack(pady=20)

    def reset_email_sender(self):
        """
        Reset sender email credentials via a popup dialog.
        Allows the user to update the sender email and password.
        """

        def save_new_email():
            new_email = email_entry.get().strip()
            new_password = password_entry.get().strip()

            if not new_email or not new_password:
                messagebox.showerror("Error", "Both fields are required!")
                return

            try:
                # Save new sender credentials
                #conn = sqlite3.connect(DB_NAME)
                conn = sqlite3.connect(SupplementClass.DB_NAME)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM sender_credentials")  # Clear existing sender credentials
                cursor.execute(
                    "INSERT INTO sender_credentials (email, encrypted_password) VALUES (?, ?)",
                    (new_email, SupplementClass.encrypt_data(new_password)),
                )
                conn.commit()
                conn.close()

                messagebox.showinfo("Success", "Sender email credentials updated successfully!",parent=self.root) # Centered messagebox
                reset_window.destroy()
            except Exception as e:
                logging.error(f"Failed to reset sender credentials: {e}")
                messagebox.showerror("Error", "Failed to update sender credentials!")

        # Popup for resetting sender email credentials
        reset_window = tk.Toplevel(self.root)
        reset_window.title("Reset Sender Email")
        reset_window.geometry("400x250")
        reset_window.configure(bg="#d1e7ff")
        reset_window.iconbitmap(SupplementClass.ICON_FILE)

        tk.Label(reset_window, text="New Sender Email:", font=("Helvetica", 12), bg="#d1e7ff").pack(pady=10)
        email_entry = ttk.Entry(reset_window, width=30)
        email_entry.pack(pady=5)

        tk.Label(reset_window, text="*New Gmail App/Zoho Password:", font=("Helvetica", 12), bg="#d1e7ff").pack(pady=10)
        password_entry = ttk.Entry(reset_window, width=30, show="*")
        password_entry.pack(pady=5)

        ttk.Button(reset_window, text="Save", command=save_new_email).pack(pady=20)

    def export_to_excel(self):
        """
        Export data to a password-protected Excel file.
        Hashed passwords are converted to plain text, and the file is protected with the admin password.
        """
        try:
            # Retrieve admin password and decrypt it
            admin_password = SupplementClass.get_admin_password("admin")
            if not admin_password:
                messagebox.showerror("Error", "Failed to retrieve admin password!")
                return

            # Fetch data from the database
            #conn = sqlite3.connect(DB_NAME)
            conn = sqlite3.connect(SupplementClass.DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT account_id, original_password, target_name FROM passwords")
            rows = cursor.fetchall()
            conn.close()

            if not rows:
                messagebox.showerror("Error", "No data available to export!")
                return

            # Create a DataFrame for Excel export
            df = pd.DataFrame(rows, columns=["Account ID", "Password", "Target Name"])

            # Generate a default file name
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            default_file_name = f"password_manager_export_{timestamp}.xlsx"

            # Ask user for save location
            file_path = tk.filedialog.asksaveasfilename(
                initialfile=default_file_name,
                defaultextension=".xlsx",
                filetypes=[("Excel Files", "*.xlsx")],
                title="Save Excel File"
            )
            if not file_path:
                return  # User canceled the save operation

            # Save the data to an Excel file
            with pd.ExcelWriter(file_path, engine="xlsxwriter") as writer:
                df.to_excel(writer, index=False, sheet_name="Passwords")
                workbook = writer.book
                worksheet = writer.sheets["Passwords"]
                worksheet.protect(password=admin_password)

            # Notify the user
            hint = f"{admin_password[:2]}****{admin_password[-2:]}"  # Provide a hint for the password
            messagebox.showinfo(
                "Export Successful",
                f"Data exported successfully and password protected!\nAdmin password hint: {hint}"
            )

        except ImportError:
            messagebox.showerror(
                "Error",
                "Required modules 'pandas' or 'xlsxwriter' are not installed. Please install them to use this feature."
            )
        except Exception as e:
            logging.error(f"Failed to export data to Excel: {e}")
            messagebox.showerror("Error", f"Failed to export data: {e}")

    def center_window(self, window, width=None, height=None):
        """
        Center a window relative to the Password Manager window.

        Args:
            window (tk.Toplevel): The window to center.
            width (int, optional): Desired width of the window. Defaults to current width.
            height (int, optional): Desired height of the window. Defaults to current height.
        """
        self.root.update_idletasks()  # Ensure main window dimensions are accurate
        x = self.root.winfo_x()
        y = self.root.winfo_y()
        root_width = self.root.winfo_width()
        root_height = self.root.winfo_height()

        # Default to current window dimensions
        if width is None or height is None:
            window.update_idletasks()
            width = width or window.winfo_width()
            height = height or window.winfo_height()

        # Calculate offsets for centering
        x_offset = x + (root_width - width) // 2
        y_offset = y + (root_height - height) // 2

        window.geometry(f"{width}x{height}+{x_offset}+{y_offset}")
        window.lift()

    def show_about_window(self):
        """
        Show the About window with application details and allow text selection, copying, and closing.
        """
        # Create a new top-level window
        about_window = tk.Toplevel(self.root)
        about_window.title("About Password Manager")
        about_window.geometry("600x500")
        about_window.configure(bg="#e6f7ff")

        # Center the window relative to the main application
        self.center_window(about_window, width=600, height=500)

        # Create a Frame for the Text widget and Scrollbar
        frame = tk.Frame(about_window, bg="#e6f7ff")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create a Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Create a Text widget for displaying content
        text_widget = tk.Text(
            frame,
            wrap=tk.WORD,
            bg="#f8f8f8",
            fg="black",
            font=("Helvetica", 12),
            yscrollcommand=scrollbar.set,
        )
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Link the Scrollbar to the Text widget
        scrollbar.config(command=text_widget.yview)

        # Add content to the Text widget
        content = """\
    Password Manager v2.0

    Developed by: Faruk Ahmed
    Version: 2.0.0
    Date: January 2025

    Description:
    A comprehensive password manager with encryption, CRUD operations, email integration, and data export features.

    Key Features:
    """
        # Append bullet points to the content
        bullet_points = [
            "1. Enhanced Security: All passwords are encrypted using AES-256.",
            "2. User-Friendly Interface: Intuitive design for easy navigation.",
            "3. Search Functionality: Quickly find stored passwords.",
            "4. Data Export: Export passwords to a password-protected Excel file.",
            "5. Conflict Resolution: Easily resolve conflicts during data imports.",
            "6. Dynamic Data Grid: Colorful, scrollable grid with alternating row colors.",
            "7. CRUD Operations: Create, Read, Update, and Delete password records.",
            "8. Real-Time Sync: Refresh the grid instantly after any update.",
            "9. Duplicate Prevention: Detects and prevents duplicate records.",
            "10. Password Retrieval: Quickly retrieve and display original passwords.",
            "11. Admin Management: Supports admin credential management with encryption.",
            "12. Log Management: Keeps track of logs and removes outdated log files.",
            "13. Multi-Format Import: Import data from various file formats like CSV and Excel.",
            "14. Summary Reports: Displays a clear summary of updates and denied records.",
            "15. Cross-Platform Compatibility: Works on Windows, macOS, and Linux.",
            "16. Customizable Appearance: Easily adjust themes and colors for the interface.",
            "17. Error Handling: Robust error handling and user-friendly error messages.",
            "18. Search with Filters: Advanced search with filters for Account ID and Target Name.",
            "19. Password Strength Validation: Ensures strong passwords during creation.",
            "20. One-Click Backup: Backup your database with a single click.",
        ]

        # Insert content and bullet points into the Text widget
        text_widget.insert(tk.END, content + "\n")
        for point in bullet_points:
            text_widget.insert(tk.END, f"• {point}\n")

        # Make the Text widget read-only
        text_widget.config(state=tk.DISABLED)

        # Add right-click context menu for copying text
        def copy_selected_text(event=None):
            """Copy selected text to the clipboard."""
            try:
                selected_text = text_widget.selection_get()
                about_window.clipboard_clear()
                about_window.clipboard_append(selected_text)
                about_window.update()  # Update clipboard
            except tk.TclError:
                messagebox.showinfo("Info", "No text selected to copy!")

        # Add a context menu for copying
        context_menu = tk.Menu(about_window, tearoff=0)
        context_menu.add_command(label="Copy", command=copy_selected_text)

        # Show context menu on right-click
        def show_context_menu(event):
            context_menu.post(event.x_root, event.y_root)

        text_widget.bind("<Button-3>", show_context_menu)  # Right-click for context menu

        # Add a Close button
        close_button = ttk.Button(
            about_window,
            text="Close",
            command=about_window.destroy,  # Close the About window
        )
        close_button.pack(pady=10)

        # Make the window modal
        about_window.transient(self.root)
        about_window.grab_set()
        about_window.focus_force()


# def show_about_window(self):
#     """Show the About window with application details and a scroll bar."""
#     about_window = tk.Toplevel(self.root)
#     about_window.title("About Password Manager")
#     about_window.geometry("400x500")
#     about_window.configure(bg="#e6f7ff")
#
#     # Center the window relative to the Password Manager window
#     self.center_window(about_window, width=600, height=300)
#
#     # Main frame for scrolling
#     main_frame = tk.Frame(about_window, bg="#e6f7ff")
#     main_frame.pack(fill=tk.BOTH, expand=True)
#
#     # Canvas for scrolling
#     canvas = tk.Canvas(main_frame, bg="#e6f7ff", highlightthickness=0)
#     canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
#
#     # Scrollbar for the canvas
#     scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
#     scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
#
#     # Configure the canvas with the scrollbar
#     canvas.configure(yscrollcommand=scrollbar.set)
#     canvas.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
#
#     # Bind mouse scrolling to the canvas
#     def on_mouse_scroll(event):
#         """Scroll the canvas when the mouse wheel is used."""
#         canvas.yview_scroll(-1 * int(event.delta / 120), "units")
#
#     canvas.bind_all("<MouseWheel>", on_mouse_scroll)
#
#     # Inner frame for the content
#     inner_frame = tk.Frame(canvas, bg="#e6f7ff")
#     canvas.create_window((0, 0), window=inner_frame, anchor="nw")
#
#     # Add content to the inner frame
#     tk.Label(
#         inner_frame,
#         text="Password Manager v2.0",
#         font=("Helvetica", 16, "bold"),
#         bg="#e6f7ff"
#     ).pack(pady=10)
#
#     # Numbered points
#     numbered_points = [
#         ("Enhanced Security:", "All passwords are encrypted using AES-256."),
#         ("User-Friendly Interface:", "Intuitive design for easy navigation."),
#         ("Search Functionality:", "Quickly find stored passwords."),
#         ("Data Export:", "Export passwords to a password-protected Excel file."),
#         ("Conflict Resolution:", "Easily resolve conflicts during data imports."),
#         ("Dynamic Data Grid:", "Colorful, scrollable grid with alternating row colors."),
#         ("CRUD Operations:", "Create, Read, Update, and Delete password records."),
#         ("Real-Time Sync:", "Refresh the grid instantly after any update."),
#         ("Duplicate Prevention:", "Detects and prevents duplicate records."),
#         ("Password Retrieval:", "Quickly retrieve and display original passwords."),
#         ("Admin Management:", "Supports admin credential management with encryption."),
#         ("Log Management:", "Keeps track of logs and removes outdated log files."),
#         ("Multi-Format Import:", "Import data from various file formats like CSV and Excel."),
#         ("Summary Reports:", "Displays a clear summary of updates and denied records."),
#         ("Cross-Platform Compatibility:", "Works on Windows, macOS, and Linux."),
#         ("Customizable Appearance:", "Easily adjust themes and colors for the interface."),
#         ("Error Handling:", "Robust error handling and user-friendly error messages."),
#         ("Search with Filters:", "Advanced search with filters for Account ID and Target Name."),
#         ("Password Strength Validation:", "Ensures strong passwords during creation."),
#         ("One-Click Backup:", "Backup your database with a single click."),
#     ]
#
#     # Fonts for styling
#     bold_font = ("Arial", 12, "bold")  # Bold and larger font for titles
#     normal_font = ("Arial", 10)  # Normal font for descriptions
#
#     # Add numbered points to the inner_frame
#     for i, (title, description) in enumerate(numbered_points, start=1):
#         # Create a text widget for each point
#         text_widget = tk.Text(inner_frame, wrap="word", bg="#e6f7ff", borderwidth=0, highlightthickness=0, height=2)
#         text_widget.pack(fill="x", padx=20, pady=5)
#
#         # Configure font tags
#         text_widget.tag_configure("bold", font=bold_font)  # Configure bold font
#         text_widget.tag_configure("normal", font=normal_font)  # Configure normal font
#
#         # Insert the number and bold title
#         text_widget.insert("end", f"{i}. ", "bold")  # Number in bold
#         text_widget.insert("end", title, "bold")  # Title in bold font
#
#         # Insert the description in normal font
#         text_widget.insert("end", f" {description}", "normal")
#
#         # Prevent user edits while allowing selection
#         def disable_edit(event):
#             return "break"  # Prevent editing actions
#
#         text_widget.bind("<Key>", disable_edit)  # Block key presses
#         text_widget.bind("<BackSpace>", disable_edit)  # Block backspace
#         text_widget.bind("<Delete>", disable_edit)  # Block delete
#
#     # Close button
#     ttk.Button(inner_frame, text="Close", command=about_window.destroy).pack(pady=20, anchor="center")
#
#     # Make the window modal
#     about_window.transient(self.root)
#     about_window.grab_set()
#     about_window.focus_force()

if __name__ == "__main__":
    # Initialize logging and database through SupplementClass
    SupplementClass.init_logging()
    SupplementClass.init_db()

    # Prepare the application icon
    icon_path = SupplementClass.prepare_icon()

    # Launch the application
    root = tk.Tk()
    app = PasswordManagerGUI(root)  # Initialize the GUI class

    # Set the program icon
    if icon_path:
        root.iconphoto(True, tk.PhotoImage(file=icon_path))

    # Start the Tkinter main loop
    root.mainloop()


