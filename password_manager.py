"""
Password Manager Script
Developed by: Faruk Ahmed
Version: 2.0.0
Date: January 2025

Description:
A comprehensive password manager with encryption, CRUD operations, email integration, and data export features.

Contact:
GitHub: https://github.com/bornaly
Email: cyberwebpen@gmail.com
"""

import io
import tkinter as tk
import webbrowser, os,sys, time
from tkinter import ttk, Menu, filedialog
from tkinter import filedialog, messagebox, simpledialog
import sqlite3
import bcrypt
from email.mime.text import MIMEText
import smtplib
from email.header import Header
from email.utils import formataddr
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os
import base64
from PIL import Image, ImageTk
import pyAesCrypt
import pandas as pd
from datetime import datetime
from tkinter import simpledialog, messagebox, Toplevel, Label, Button, ttk

BUFFER_SIZE = 64 * 1024  # Buffer size for AES encryption/decryption


class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        widget.bind("<Enter>", self.show_tooltip)
        widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.geometry(f"+{x}+{y}")
        label = tk.Label(
            self.tooltip, text=self.text, bg="#FFFFE0", fg="black",
            font=("Helvetica", 10), borderwidth=1, relief="solid"
        )
        label.pack()

    def hide_tooltip(self, event):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

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

        cursor.execute("""
                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)

        # Insert default value for inactivity timeout if not already present
        cursor.execute("""
            INSERT OR IGNORE INTO app_settings (key, value)
            VALUES ('inactivity_timeout', '300000')  -- Default: 5 minutes in milliseconds
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

    @classmethod
    def fetch_inactivity_timeout(cls):
        try:
            conn = sqlite3.connect(cls.DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM app_settings WHERE key = 'inactivity_timeout'")
            result = cursor.fetchone()
            conn.close()
            return int(result[0]) if result else 5  # Default to 5 minutes
        except Exception as e:
            logging.error(f"Error fetching inactivity timeout: {e}")
            return 5  # Default to 5 minutes


class PasswordManagerGUI:
    """
    GUI for Password Manager, including Tools and Maintenance menus with CRUD functionality.
    """

    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager 2.0")
        #self.root.geometry("900x775")  # Set the window size
        self.root.geometry("950x770")  # Set the window size
        self.center_window(self.root)  # Center the window
        self.root.configure(bg="#e6f7ff")

        # Set the window as visible and ensure focus
        self.root.lift()
        self.root.attributes("-topmost", True)
        self.root.attributes("-topmost", False)

        # Fetch timeout from database (default to 3 minutes)
        self.inactivity_timeout = 3 * 60  # 3 minutes (in seconds)
        self.last_activity_time = time.time()

        # Bind activity events
        self.root.bind("<Any-KeyPress>", self.reset_inactivity_timer)
        self.root.bind("<Motion>", self.reset_inactivity_timer)

        # Start inactivity tracker
        self.start_inactivity_tracker()

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
            # Show splash screen first, then main UI
            self.show_splash_screen()
            self.authenticate_admin()

    def reset_inactivity_timer(self, event=None):
        """Reset the inactivity timer on user activity."""
        self.last_activity_time = time.time()

    def start_inactivity_tracker(self):
        """Continuously check for inactivity and disable the main window if timeout occurs."""

        def check_inactivity():
            # Call the inactivity_time method with correct arguments
            timeout_occurred, remaining_time = self.inactivity_time(self.last_activity_time, self.inactivity_timeout)

            if timeout_occurred:
                self.disable_main_window()
            else:
                #print(f"Remaining time before timeout: {remaining_time} seconds")
                self.root.after(1000, check_inactivity)  # Check every second

        self.root.after(1000, check_inactivity)

    def disable_main_window(self):
        """Disable the main window and show the Login Password Manager window."""
        self.root.attributes("-disabled", True)  # Disable the main window
        self.show_login_window()

    def enable_main_window(self):
        """Re-enable the main window after successful re-login."""
        self.root.attributes("-disabled", False)  # Re-enable the main window

    def show_login_window(self):
        """Display the Login Password Manager window for re-authentication."""
        self.authenticate_admin()  # Call the existing login method

    def terminate_program(self):
        """Terminate the entire program if the login window is closed."""
        self.root.destroy()
        sys.exit(0)  # Force termination

    def authenticate_admin(self):
        """Authenticate the admin user using the existing Login Password Manager window."""
        def validate_admin():
            admin_id = admin_id_entry.get().strip()
            admin_password = admin_password_entry.get().strip()
            try:
                conn = sqlite3.connect("password_manager.db")
                cursor = conn.cursor()
                cursor.execute("SELECT encrypted_password FROM admin WHERE admin_id = ?", (admin_id,))
                result = cursor.fetchone()
                conn.close()
                if result and self.verify_password(admin_password, result[0]):
                    messagebox.showinfo("Success", "Admin authenticated successfully!", parent=login_window)
                    login_window.destroy()
                    self.enable_main_window()
                else:
                    messagebox.showerror("Error", "Invalid Admin Credentials!", parent=login_window)
            except Exception as e:
                messagebox.showerror("Error", f"Authentication failed: {e}", parent=login_window)

        def cancel_login():
            if messagebox.askyesno("Confirm Exit", "Are you sure you want to exit the application?",
                                   parent=login_window):
                self.terminate_program()

        # Create the login window
        login_window = tk.Toplevel(self.root)
        login_window.title("Login Password Manager")
        login_window.geometry("400x300")
        login_window.transient(self.root)
        login_window.grab_set()
        login_window.protocol("WM_DELETE_WINDOW", cancel_login)

        tk.Label(login_window, text="Username:").pack(pady=10)
        admin_id_entry = ttk.Entry(login_window)
        admin_id_entry.pack(pady=5)

        tk.Label(login_window, text="Password:").pack(pady=10)
        admin_password_entry = ttk.Entry(login_window, show="*")
        admin_password_entry.pack(pady=5)

        ttk.Button(login_window, text="Login", command=validate_admin).pack(pady=20)
        ttk.Button(login_window, text="Cancel", command=cancel_login).pack(pady=5)

    def verify_password(self, password, encrypted_password):
        """Verify the entered password with the encrypted password."""
        return password == encrypted_password  # Replace with actual decryption logic

    @classmethod
    def fetch_inactivity_timeout(cls):
        try:
            conn = sqlite3.connect(cls.DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM app_settings WHERE key = 'inactivity_timeout'")
            result = cursor.fetchone()
            conn.close()
            return int(result[0]) if result else 5  # Default to 5 minutes
        except Exception as e:
            logging.error(f"Error fetching inactivity timeout: {e}")
            return 5  # Default to 5 minutes

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
        Features modern styling, a cancel button, and improved layout.
        """

        def save_admin_credentials():
            """Save the admin credentials and proceed."""
            admin_id = admin_id_entry.get().strip()
            admin_password = admin_password_entry.get().strip()

            if not admin_id or not admin_password:
                messagebox.showerror("Error", "All fields are required!")
                return

            try:
                # Save admin credentials securely
                SupplementClass.save_admin_credentials(admin_id, admin_password)

                messagebox.showinfo("Success", "Admin credentials saved successfully!", parent=self.root)
                admin_window.destroy()
                self.authenticate_admin()  # Proceed to authenticate admin

            except Exception as e:
                logging.error(f"Failed to save admin credentials: {e}")
                messagebox.showerror("Error", f"Failed to save admin credentials: {e}")

        def cancel_admin_setup():
            """
            Cancel the admin setup process and close both windows.
            """
            if messagebox.askyesno("Cancel Setup",
                                   "Are you sure you want to cancel the setup? This will close the application."):
                admin_window.destroy()
                self.root.destroy()

        # Create the admin credentials setup window
        admin_window = tk.Toplevel(self.root)
        admin_window.title("Setup Admin Credentials")
        admin_window.configure(bg="#e6f7ff")
        admin_window.resizable(False, False)

        # Center the window relative to Password Manager
        admin_width = 450
        admin_height = 350
        root_x = self.root.winfo_x()
        root_y = self.root.winfo_y()
        root_width = self.root.winfo_width()
        root_height = self.root.winfo_height()

        admin_x = root_x + (root_width // 2) - (admin_width // 2)
        admin_y = root_y + (root_height // 2) - (admin_height // 2)
        admin_window.geometry(f"{admin_width}x{admin_height}+{admin_x}+{admin_y}")

        admin_window.transient(self.root)
        admin_window.grab_set()
        admin_window.focus_force()

        # Title
        tk.Label(
            admin_window,
            text="Setup Admin Credentials",
            font=("Helvetica", 16, "bold"),
            bg="#4682B4",
            fg="white",
            relief="raised",
            pady=10
        ).pack(fill=tk.X)

        # Admin ID Field
        tk.Label(admin_window, text="Create Admin ID:", font=("Helvetica", 12), bg="#e6f7ff").pack(pady=10)
        admin_id_entry = ttk.Entry(admin_window, width=40)
        admin_id_entry.pack(pady=5)

        # Admin Password Field
        tk.Label(admin_window, text="Create Admin Password:", font=("Helvetica", 12), bg="#e6f7ff").pack(pady=10)
        admin_password_entry = ttk.Entry(admin_window, width=40, show="*")
        admin_password_entry.pack(pady=5)

        # Password Hint
        tk.Label(
            admin_window,
            text="* Make sure to remember this password.",
            font=("Helvetica", 10, "italic"),
            fg="gray",
            bg="#e6f7ff",
        ).pack(pady=5)

        # Button Frame
        button_frame = tk.Frame(admin_window, bg="#e6f7ff")
        button_frame.pack(pady=20)

        # Save Button
        save_button = tk.Button(
            button_frame,
            text="Save",
            font=("Helvetica", 12, "bold"),
            bg="#4CAF50",  # Green
            fg="white",
            activebackground="#45a049",
            activeforeground="white",
            command=save_admin_credentials
        )
        save_button.grid(row=0, column=0, padx=10)

        # Cancel Button
        cancel_button = tk.Button(
            button_frame,
            text="Cancel",
            font=("Helvetica", 12, "bold"),
            bg="#F44336",  # Red
            fg="white",
            activebackground="#e53935",
            activeforeground="white",
            command=cancel_admin_setup
        )
        cancel_button.grid(row=0, column=1, padx=10)

        # Bind Enter key to activate the Save button
        admin_window.bind("<Return>", lambda event: save_button.invoke())
        save_button.focus_set()

    def show_splash_screen(self):
        import time
        """
        Display a fancy splash screen centered on the Password Manager window.
        Features include a gradient background, progress bar, and enhanced text styling.
        """
        logging.info("Password Manager initialized. Developed by Faruk Ahmed.")  # Log initialization

        # Create the splash screen as a Toplevel window
        splash = tk.Toplevel(self.root)
        splash.title("Welcome")
        splash.configure(bg="#333333")  # Darker background for contrast
        splash.overrideredirect(True)  # Remove window borders
        splash.resizable(False, False)

        # Center the splash screen relative to the Password Manager window
        splash_width, splash_height = 500, 400
        root_x = self.root.winfo_x()
        root_y = self.root.winfo_y()
        root_width = self.root.winfo_width()
        root_height = self.root.winfo_height()

        splash_x = root_x + (root_width // 2) - (splash_width // 2)
        splash_y = root_y + (root_height // 2) - (splash_height // 2)
        splash.geometry(f"{splash_width}x{splash_height}+{splash_x}+{splash_y}")

        # Gradient background simulation using canvas
        canvas = tk.Canvas(splash, width=splash_width, height=splash_height, highlightthickness=0)
        canvas.pack(fill=tk.BOTH, expand=True)
        for i in range(256):
            color = f"#{i:02x}{i:02x}ff"  # Blue gradient
            canvas.create_rectangle(0, i * (splash_height // 256), splash_width, (i + 1) * (splash_height // 256),
                                    fill=color, outline="")

        # Add content to the splash screen
        text_shadow_offset = 2  # Offset for the shadow

        # Title text with shadow
        canvas.create_text(
            splash_width // 2 + text_shadow_offset, 100 + text_shadow_offset,
            text="Welcome to Password Manager 2.0",
            font=("Helvetica", 20, "bold italic"),
            fill="black"  # Shadow color
        )
        canvas.create_text(
            splash_width // 2, 100,
            text="Welcome to Password Manager 2.0",
            font=("Helvetica", 20, "bold italic"),
            fill="#FFD700"  # Gold color
        )

        # Developer details with enhanced visibility (bright cyan)
        canvas.create_text(
            splash_width // 2 + text_shadow_offset, 200 + text_shadow_offset,
            text="Developed by Faruk Ahmed\nDate: Jan/2025\n",
            font=("Helvetica", 16),
            fill="black"  # Shadow color
        )
        canvas.create_text(
            splash_width // 2, 200,
            text="Developed by Faruk Ahmed\nDate: Jan/2025\n",
            font=("Helvetica", 16),
            fill="#00FFFF"  # Cyan color for high visibility
        )

        # Contact details with enhanced visibility (lime green)
        canvas.create_text(
            splash_width // 2 + text_shadow_offset, 260 + text_shadow_offset,
            text="\nGitHub: https://github.com/bornaly\n\nEmail: cyberwebpen@gmail.com",
            font=("Helvetica", 14),
            fill="black"  # Shadow color
        )
        canvas.create_text(
            splash_width // 2, 260,
            text="\nGitHub: https://github.com/bornaly\n\nEmail: cyberwebpen@gmail.com",
            font=("Helvetica", 14),
            fill="#32CD32"  # Lime green for high visibility
        )

        # Add a progress bar at the bottom
        progress_frame = tk.Frame(splash, bg="#333333")
        progress_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(20, 0))
        progress = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=splash_width - 50, mode="determinate")
        progress.pack(pady=10)

        # Simulate progress bar filling
        def simulate_loading():
            for value in range(101):
                splash.update_idletasks()  # Allow UI to update
                progress["value"] = value
                time.sleep(0.03)  # Adjust speed of loading
            self.transition_to_main_app(splash)  # Transition to the main application

        # Delay and show the splash screen with progress simulation
        self.root.after(550, simulate_loading)

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
        Features modern styling, a cancel button, and improved layout.
        """

        def save_email():
            """Save the email credentials and proceed."""
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


        def cancel_email_setup():
            """
            Cancel the email setup process and close both windows.
            """
            if messagebox.askyesno("Cancel Setup",
                                   "Are you sure you want to cancel the setup? This will close the application."):
                sender_window.destroy()
                self.root.destroy()

        def show_gmail_guide():
            """Show Gmail App Password setup guide."""
            guide_window = tk.Toplevel(self.root)
            guide_window.title("How to Setup Gmail App Password")
            guide_window.geometry("500x300")
            guide_window.configure(bg="#f7f9fc")

            steps = [
                "[1]  Sign in to your Google Account",
                "[2]  In the left navigation panel, go to 'Security'",
                "[3]  Under the 'Signing in to Google' section, select 'App passwords'",
                "[4]  At the bottom of the page, click 'Select app' and choose the app you're using",
                "[5]  Then, click 'Select device' and choose the device you're using",
                "[6]  Finally, click 'Generate' to create a 16-character App Password"
            ]


            tk.Label(guide_window, text="Follow these steps:", font=("Helvetica", 12, "bold"), bg="#f7f9fc").pack(
                pady=10)
            for step in steps:
                tk.Label(guide_window, text=step, font=("Helvetica", 12), bg="#f7f9fc", anchor="w").pack(anchor="w",
                                                                                                         padx=20)

            link_label = tk.Label(
                guide_window, text="Open Gmail App Password Page", font=("Helvetica", 12, "underline"), fg="blue",
                bg="#f7f9fc", cursor="hand2"
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
        sender_window.configure(bg="#e6f7ff")
        sender_window.resizable(False, False)

        # Center the window relative to Password Manager
        sender_width = 450
        sender_height = 450
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

        # Title
        tk.Label(
            sender_window,
            text="Setup Sender Email",
            font=("Helvetica", 16, "bold"),
            bg="#4682B4",
            fg="white",
            relief="raised",
            pady=10
        ).pack(fill=tk.X)

        # Sender Email Field
        tk.Label(sender_window, text="Sender Email:", font=("Helvetica", 12), bg="#e6f7ff").pack(pady=10)
        email_entry = ttk.Entry(sender_window, width=40)
        email_entry.pack(pady=5)

        # Gmail App Password Field
        tk.Label(sender_window, text="Gmail App Password:", font=("Helvetica", 12), bg="#e6f7ff").pack(pady=10)
        password_entry = ttk.Entry(sender_window, width=40, show="*")
        password_entry.pack(pady=5)

        # Password Hint
        tk.Label(
            sender_window,
            text="* Example: qwer trew rtyu qsde",
            font=("Helvetica", 10, "italic"),
            fg="gray",
            bg="#e6f7ff",
        ).pack(pady=5)

        # Receiver Email Field
        tk.Label(sender_window, text="Receiver Email:", font=("Helvetica", 12), bg="#e6f7ff").pack(pady=10)
        receiver_email_entry = ttk.Entry(sender_window, width=40)
        receiver_email_entry.pack(pady=5)

        # Gmail Setup Guide Link
        link_label = tk.Label(
            sender_window, text="How to setup Gmail App password?", font=("Helvetica", 12, "underline"), fg="blue",
            bg="#e6f7ff", cursor="hand2"
        )
        link_label.pack(pady=5)
        link_label.bind("<Button-1>", lambda e: show_gmail_guide())

        # Button Frame
        button_frame = tk.Frame(sender_window, bg="#e6f7ff")
        button_frame.pack(pady=20)

        # Save Button
        save_button = tk.Button(
            button_frame,
            text="Save",
            font=("Helvetica", 12, "bold"),
            bg="#4CAF50",  # Green
            fg="white",
            activebackground="#45a049",
            activeforeground="white",
            command=save_email
        )
        save_button.grid(row=0, column=0, padx=10)

        # Cancel Button
        cancel_button = tk.Button(
            button_frame,
            text="Cancel",
            font=("Helvetica", 12, "bold"),
            bg="#F44336",  # Red
            fg="white",
            activebackground="#e53935",
            activeforeground="white",
            command=cancel_email_setup
        )
        cancel_button.grid(row=0, column=1, padx=10)

        sender_window.bind("<Return>", lambda event: save_button.invoke())
        save_button.focus_set()

    def authenticate_admin(self):
        """
        Authenticate the admin user at the start of the application.
        Centers the Admin Login window relative to the Password Manager window.
        Adds an icon above the title and placeholder text to Username and Password fields.
        """

        def validate_admin():
            admin_id = admin_id_entry.get().strip()
            admin_password = admin_password_entry.get().strip()
            try:
                conn = sqlite3.connect(SupplementClass.DB_NAME)
                cursor = conn.cursor()
                cursor.execute("SELECT encrypted_password FROM admin WHERE admin_id = ?", (admin_id,))
                result = cursor.fetchone()
                conn.close()
                if result and SupplementClass.decrypt_data(result[0]) == admin_password:
                    messagebox.showinfo("Success", "Admin authenticated successfully!", parent=self.root)
                    login_window.destroy()
                    self.setup_main_ui()
                else:
                    messagebox.showerror("Error", "Invalid Admin Credentials!", parent=login_window)
            except Exception as e:
                logging.error(f"Admin authentication failed: {e}")
                messagebox.showerror("Error", f"Authentication failed: {e}", parent=login_window)

        def cancel_login():
            if messagebox.askyesno("Confirm Exit", "Are you sure you want to exit the application?",
                                   parent=login_window):
                self.root.destroy()
                sys.exit(0)

        # Create the login window
        login_window = tk.Toplevel(self.root)
        login_window.title("Login Password Manager")
        login_window.geometry("500x400")
        login_window.configure(bg="#333333")
        login_window.transient(self.root)
        login_window.grab_set()
        login_window.focus_force()
        login_window.attributes("-topmost", True)
        login_window.attributes("-topmost", False)

        # Center the login window
        window_width, window_height = 500, 400
        root_x = self.root.winfo_x()
        root_y = self.root.winfo_y()
        root_width = self.root.winfo_width()
        root_height = self.root.winfo_height()
        login_x = root_x + (root_width // 2) - (window_width // 2)
        login_y = root_y + (root_height // 2) - (window_height // 2)
        login_window.geometry(f"{window_width}x{window_height}+{login_x}+{login_y}")

        # Gradient background using canvas
        gradient_canvas = tk.Canvas(login_window, width=500, height=400, bg="#333333", highlightthickness=0)
        gradient_canvas.pack(fill=tk.BOTH, expand=True)

        for i in range(256):
            color = f"#{i:02x}{i:02x}ff"
            gradient_canvas.create_line(0, i * 2, 500, i * 2, fill=color, width=2)

        # Add icon above the title
        icon_path = os.path.join(os.path.dirname(__file__), "safe_icon.png")
        print(f"Resolved icon path: {icon_path}")
        if os.path.exists(icon_path):
            try:
                original_image = Image.open(icon_path)
                resized_image = original_image.resize((80, 80), Image.Resampling.LANCZOS)  # Use LANCZOS for resizing
                self.icon_image = ImageTk.PhotoImage(resized_image)
                gradient_canvas.create_image(250, 60, image=self.icon_image)
                gradient_canvas.update()
                print("Icon successfully loaded and displayed!")
            except Exception as e:
                print(f"Error loading or displaying icon: {e}")
        else:
            print(f"Icon file not found at {icon_path}. Ensure the path is correct.")

        # Add title below the icon
        gradient_canvas.create_text(
            250, 150,
            text="Welcome to Password Manager 2.0",
            font=("Helvetica", 18, "bold italic"),
            fill="#FFD700"
        )
        # Add placeholder logic for Username and Password fields
        def add_placeholder(entry, placeholder_text, show=""):
            """
            Add placeholder text to an entry widget. Removes it when focused and restores if empty.
            Handles password masking when 'show' is specified.
            """

            def on_focus_in(event):
                if entry.get() == placeholder_text:
                    entry.delete(0, tk.END)
                    entry.configure(foreground="black", show=show)  # Set text color and enable masking if applicable

            def on_focus_out(event):
                if entry.get().strip() == "":
                    entry.insert(0, placeholder_text)
                    entry.configure(foreground="gray", show="")  # Restore placeholder text and disable masking

            entry.insert(0, placeholder_text)
            entry.configure(foreground="gray", show="")  # Placeholder text color, no masking
            entry.bind("<FocusIn>", on_focus_in)
            entry.bind("<FocusOut>", on_focus_out)

        # Username entry with placeholder
        admin_id_entry = ttk.Entry(login_window, font=("Helvetica", 14), justify="center")
        gradient_canvas.create_window(250, 200, window=admin_id_entry, width=300, height=40)
        add_placeholder(admin_id_entry, "Enter Username")

        # Password entry with placeholder and password masking
        admin_password_entry = ttk.Entry(login_window, font=("Helvetica", 14), justify="center")
        gradient_canvas.create_window(250, 260, window=admin_password_entry, width=300, height=40)
        add_placeholder(admin_password_entry, "Enter Password", show="*")

        # Buttons with custom colors and spacing
        def on_hover(button, color):
            button["background"] = color

        def on_leave(button, color):
            button["background"] = color

        # Login button (green) with focus
        login_button = tk.Button(
            login_window,
            text="Login",
            font=("Helvetica", 14, "bold"),
            bg="#4CAF50",  # Green background
            fg="white",
            activebackground="#45a049",  # Darker green on hover
            activeforeground="white",
            relief=tk.RAISED,
            command=validate_admin
        )
        gradient_canvas.create_window(180, 320, window=login_button, width=120, height=40)
        login_button.bind("<Enter>", lambda e: on_hover(login_button, "#45a049"))
        login_button.bind("<Leave>", lambda e: on_leave(login_button, "#4CAF50"))
        login_button.focus_set()  # Set default focus to the Login button

        # Cancel button (red) with spacing
        cancel_button = tk.Button(
            login_window,
            text="Cancel",
            font=("Helvetica", 14, "bold"),
            bg="#F44336",  # Red background
            fg="white",
            activebackground="#e53935",  # Darker red on hover
            activeforeground="white",
            relief=tk.RAISED,
            command=cancel_login
        )
        gradient_canvas.create_window(320, 320, window=cancel_button, width=120, height=40)
        cancel_button.bind("<Enter>", lambda e: on_hover(cancel_button, "#e53935"))
        cancel_button.bind("<Leave>", lambda e: on_leave(cancel_button, "#F44336"))

        # Bind Enter key to activate the Login button
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

            # Add Footer Section for Total Records
            footer_frame = tk.Frame(self.root, bg="#4682B4", height=50)
            footer_frame.pack(side=tk.BOTTOM, fill=tk.X)

            # Prevent footer frame from resizing to fit contents
            footer_frame.pack_propagate(False)

            # Add a canvas for precise positioning
            footer_canvas = tk.Canvas(footer_frame, bg="#4682B4", highlightthickness=0)
            footer_canvas.pack(fill=tk.BOTH, expand=True)

            # Add the label on the canvas
            total_records_label = tk.Label(
                footer_canvas,
                text=f"Total Records: {self.get_total_records_count()}",
                font=("Helvetica", 12, "bold"),
                bg="#4682B4",
                fg="white"
            )

            # Capture the item ID returned by create_window
            label_item_id = footer_canvas.create_window(
                footer_canvas.winfo_width() // 2,  # Center horizontally
                footer_canvas.winfo_height() // 2 - 10,  # Raise it slightly
                window=total_records_label,
                anchor="center"
            )

            # Dynamically refresh footer count
            self.refresh_footer = lambda: total_records_label.config(
                text=f"Total Records: {self.get_total_records_count()}"
            )

            # Ensure the canvas updates its size dynamically
            def update_canvas_size(event):
                # Use the stored item ID to update the position of the label
                footer_canvas.coords(
                    label_item_id,  # Use the item ID
                    footer_canvas.winfo_width() // 2,
                    footer_canvas.winfo_height() // 2 - 10
                )

            footer_canvas.bind("<Configure>", update_canvas_size)

            # Force refresh the root window
            self.root.update_idletasks()

            # Dynamically refresh footer count
            self.refresh_footer = lambda: total_records_label.config(
                text=f"Total Records: {self.get_total_records_count()}"
            )

            # Force refresh the root window
            self.root.update()
            logging.debug("Main UI setup completed and root window updated.")  # Debug statement

        except Exception as e:
            logging.error(f"Error during setup_main_ui: {e}")
            messagebox.showerror("Error", f"Failed to set up the main UI: {e}")

    def get_total_records_count(self):
        """
        Fetch total record count from the database.
        """
        try:
            conn = sqlite3.connect(SupplementClass.DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM passwords")
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception as e:
            logging.error(f"Error fetching total records count: {e}")
            return 0

    def upload_data(self):
        """
        Opens a file dialog to upload data and processes it based on user selection.
        Allows flexible column matching, previews data, and supports 'override' or 'append' modes.
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

        # Normalize column names for flexibility
        df.columns = df.columns.str.strip().str.lower()  # Remove spaces and convert to lowercase
        required_columns = {"account id", "password", "target name"}
        #required_columns = {"account id", "original_password", "target name"}

        # Validate columns
        if not required_columns.issubset(df.columns):
            messagebox.showerror(
                "Error",
                "The file must contain 'Account ID', 'Password', and 'Target Name' columns."
            )
            return

        # Show a preview of the uploaded data
        self.preview_data(df)

        # Show options to user
        def process_selection(mode):
            self.process_uploaded_data(df, mode)
            selection_window.destroy()

        selection_window = tk.Toplevel(self.root)
        selection_window.title("Data Upload Mode")
        selection_window.geometry("400x200")
        selection_window.configure(bg="#d1e7ff")

        tk.Label(
            selection_window,
            text="Choose Upload Mode:",
            font=("Helvetica", 14),
            bg="#d1e7ff"
        ).pack(pady=20)

        ttk.Button(
            selection_window,
            text="Complete Override",
            command=lambda: process_selection("override")
        ).pack(pady=10)

        ttk.Button(
            selection_window,
            text="Append New Data",
            command=lambda: process_selection("append")
        ).pack(pady=10)

        selection_window.transient(self.root)
        selection_window.grab_set()
        selection_window.focus_force()

    def preview_data(self, df):
        """
        Displays a preview window for the uploaded data.

        Args:
            df (pd.DataFrame): The uploaded data to preview.
        """
        preview_window = tk.Toplevel(self.root)
        preview_window.title("Data Preview")
        preview_window.geometry("800x400")
        preview_window.configure(bg="#e6f7ff")

        tk.Label(
            preview_window,
            text="Preview of Uploaded Data",
            font=("Helvetica", 14, "bold"),
            bg="#e6f7ff"
        ).pack(pady=10)

        frame = tk.Frame(preview_window, bg="#e6f7ff")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        canvas = tk.Canvas(frame, bg="#e6f7ff")
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        inner_frame = tk.Frame(canvas, bg="#e6f7ff")
        canvas.create_window((0, 0), window=inner_frame, anchor="nw")
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Add column headers
        for col_idx, col_name in enumerate(df.columns):
            tk.Label(
                inner_frame,
                text=col_name,
                font=("Helvetica", 12, "bold"),
                bg="#4682B4",
                fg="white",
                width=20
            ).grid(row=0, column=col_idx, padx=5, pady=5, sticky="nsew")

        # Add data rows
        for row_idx, row_data in enumerate(df.values):
            for col_idx, cell_value in enumerate(row_data):
                bg_color = "#F0F8FF" if row_idx % 2 == 0 else "#E6E6FA"
                tk.Label(
                    inner_frame,
                    text=str(cell_value),
                    font=("Helvetica", 12),
                    bg=bg_color,
                    width=20
                ).grid(row=row_idx + 1, column=col_idx, padx=5, pady=5, sticky="nsew")

        # Update scroll region
        inner_frame.update_idletasks()
        canvas.configure(scrollregion=canvas.bbox("all"))

        # Close Button
        ttk.Button(preview_window, text="Close", command=preview_window.destroy).pack(pady=10)

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
        Before exposing the password, challenge the user to enter the admin password.
        Only one row can be selected at a time for retrieval.
        """
        selected_items = self.table.selection()

        # Check if more than one row is selected
        if len(selected_items) > 1:
            messagebox.showerror("Error", "Please select only one row at a time to retrieve the password!")
            return

        if selected_items:
            # If a single record is selected, use it for retrieval
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

                # Create the admin password verification window
                def verify_admin_password():
                    entered_password = admin_password_entry.get().strip()

                    try:
                        conn = sqlite3.connect(SupplementClass.DB_NAME)
                        cursor = conn.cursor()
                        cursor.execute("SELECT encrypted_password FROM admin WHERE admin_id = ?", ("admin",))
                        admin_data = cursor.fetchone()
                        conn.close()

                        if admin_data and SupplementClass.decrypt_data(admin_data[0]) == entered_password:
                            # Correct admin password, open password retrieval window
                            verify_window.destroy()
                            show_retrieve_window(original_password)
                        else:
                            messagebox.showerror("Error", "Incorrect admin password!", parent=verify_window)

                    except Exception as e:
                        logging.error(f"Failed to verify admin password: {e}")
                        messagebox.showerror("Error", "Failed to verify admin password.", parent=verify_window)

                def cancel_verification():
                    """Cancel the verification process."""
                    verify_window.destroy()

                # Admin verification window
                verify_window = tk.Toplevel(self.root)
                verify_window.title("Admin Password Verification")
                verify_window.geometry("400x200")
                self.center_window(verify_window)
                verify_window.configure(bg="#e6f7ff")  # Match Password Manager's background color
                verify_window.transient(self.root)
                verify_window.grab_set()

                tk.Label(
                    verify_window,
                    text="Admin Password Verification",
                    font=("Helvetica", 16, "bold italic"),
                    bg="#e6f7ff",
                    fg="#333333"  # Darker text for contrast
                ).pack(pady=10)

                tk.Label(
                    verify_window,
                    text="Enter Admin Password to Expose the Password:",
                    font=("Helvetica", 12),
                    bg="#e6f7ff"
                ).pack(pady=10)

                admin_password_entry = ttk.Entry(verify_window, width=30, show="*")
                admin_password_entry.pack(pady=5)

                # Buttons with vibrant colors
                button_frame = tk.Frame(verify_window, bg="#e6f7ff")
                button_frame.pack(pady=10)

                verify_button = tk.Button(
                    button_frame,
                    text="Verify",
                    command=verify_admin_password,
                    font=("Helvetica", 12, "bold"),
                    bg="#4CAF50",  # Green background
                    fg="white",
                    activebackground="#45a049",  # Darker green on hover
                    activeforeground="white",
                    relief=tk.RAISED,
                    bd=2
                )
                verify_button.pack(side=tk.LEFT, padx=5)

                cancel_button = tk.Button(
                    button_frame,
                    text="Cancel",
                    command=cancel_verification,
                    font=("Helvetica", 12, "bold"),
                    bg="#F44336",  # Red background
                    fg="white",
                    activebackground="#e53935",  # Darker red on hover
                    activeforeground="white",
                    relief=tk.RAISED,
                    bd=2
                )
                cancel_button.pack(side=tk.LEFT, padx=5)

                verify_window.bind("<Return>", lambda event: verify_admin_password())
                admin_password_entry.focus_set()

            else:
                messagebox.showerror("Error", "No matching record found!")

        except Exception as e:
            logging.error(f"Error retrieving password: {e}")
            messagebox.showerror("Error", "An error occurred while retrieving the password. Check logs for details.")

        def show_retrieve_window(original_password):
            """
            Show the password retrieval window after successful admin verification.
            """
            retrieve_window = tk.Toplevel(self.root)
            retrieve_window.title("Retrieve Password")
            retrieve_window.geometry("600x300")
            self.center_window(retrieve_window)
            retrieve_window.configure(bg="#e6f7ff")

            # Account ID
            tk.Label(retrieve_window, text="Account ID:", font=("Helvetica", 12), bg="#e6f7ff", anchor="w").grid(
                row=0, column=0, padx=10, pady=10, sticky="w"
            )
            tk.Label(retrieve_window, text=account_id, font=("Helvetica", 10), bg="#F0F8FF", width=30,
                     anchor="w").grid(
                row=0, column=1, padx=10, pady=10, sticky="w"
            )

            # Target Name
            tk.Label(retrieve_window, text="Target Name:", font=("Helvetica", 12), bg="#e6f7ff", anchor="w").grid(
                row=1, column=0, padx=10, pady=10, sticky="w"
            )
            tk.Label(retrieve_window, text=target_name, font=("Helvetica", 10), bg="#F0F8FF", width=30,
                     anchor="w").grid(
                row=1, column=1, padx=10, pady=10, sticky="w"
            )

            # Password
            tk.Label(retrieve_window, text="Password:", font=("Helvetica", 12), bg="#e6f7ff", anchor="w").grid(
                row=2, column=0, padx=10, pady=10, sticky="w"
            )
            password_label = tk.Label(retrieve_window, text="********", font=("Helvetica", 12), bg="yellow", width=30,
                                      anchor="w")
            password_label.grid(row=2, column=1, padx=10, pady=10, sticky="w")

            def expose_password():
                """Unmask and display the original password."""
                expose_button.config(state="disabled")
                password_label.config(text=original_password)

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
            expose_button.grid(row=2, column=2, padx=10, pady=10)

            # Close Button
            ttk.Button(retrieve_window, text="Close", command=retrieve_window.destroy).grid(
                row=3, column=0, columnspan=3, pady=20, sticky="n"
            )

    def edit_selected(self):
        """
        Open a new window to edit the selected record from the grid.
        Challenges the user with an admin password before exposing the original password.
        Allows modification of Account ID, Password, and Target Name.
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
        edit_window.geometry("500x350")
        edit_window.configure(bg="#e6f7ff")
        self.center_window(edit_window)
        edit_window.transient(self.root)
        edit_window.grab_set()

        # Account ID
        tk.Label(edit_window, text="Account ID:", font=("Helvetica", 12), bg="#e6f7ff").grid(row=0, column=0, padx=10,
                                                                                             pady=10, sticky="w")
        account_id_entry = ttk.Entry(edit_window, font=("Helvetica", 12), width=30)
        account_id_entry.insert(0, old_account_id)
        account_id_entry.grid(row=0, column=1, padx=10, pady=10)

        # Password
        tk.Label(edit_window, text="Password:", font=("Helvetica", 12), bg="#e6f7ff").grid(row=1, column=0, padx=10,
                                                                                           pady=10, sticky="w")
        password_entry = ttk.Entry(edit_window, font=("Helvetica", 12), width=25, show="*")
        password_entry.insert(0, "********")  # Masked initially
        password_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        # Admin Password Verification
        def verify_admin_password(admin_password_entry, verify_window):
            """
            Verify admin password to expose the original password.
            """
            admin_password = admin_password_entry.get().strip()
            try:
                conn = sqlite3.connect(SupplementClass.DB_NAME)
                cursor = conn.cursor()
                cursor.execute("SELECT encrypted_password FROM admin WHERE admin_id = ?", ("admin",))
                admin_data = cursor.fetchone()
                conn.close()

                if admin_data and SupplementClass.decrypt_data(admin_data[0]) == admin_password:
                    # Correct admin password; expose the password
                    verify_window.destroy()
                    password_entry.config(show="")  # Remove masking
                    password_entry.delete(0, tk.END)
                    password_entry.insert(0, original_password)
                else:
                    messagebox.showerror("Error", "Incorrect admin password. Please try again!", parent=verify_window)
                    admin_password_entry.delete(0, tk.END)
            except Exception as e:
                logging.error(f"Admin password verification failed: {e}")
                messagebox.showerror("Error", "Failed to verify admin password.", parent=verify_window)

        def expose_password():
            """
            Open admin password verification window to expose the original password.
            """
            verify_window = tk.Toplevel(edit_window)
            verify_window.title("Admin Password Verification")
            verify_window.geometry("400x200")
            self.center_window(verify_window)
            verify_window.configure(bg="#e6f7ff")
            verify_window.transient(edit_window)
            verify_window.grab_set()

            tk.Label(
                verify_window,
                text="Admin Password Verification",
                font=("Helvetica", 16, "bold italic"),
                bg="#e6f7ff",
                fg="#333333"
            ).pack(pady=10)

            tk.Label(
                verify_window,
                text="Enter Admin Password to Expose the Password:",
                font=("Helvetica", 12),
                bg="#e6f7ff"
            ).pack(pady=10)

            admin_password_entry = ttk.Entry(verify_window, width=30, show="*")
            admin_password_entry.pack(pady=5)

            # Button frame for alignment
            button_frame = tk.Frame(verify_window, bg="#e6f7ff")
            button_frame.pack(pady=10)

            # Verify button
            verify_button = tk.Button(
                button_frame,
                text="Verify",
                command=lambda: verify_admin_password(admin_password_entry, verify_window),
                bg="#4CAF50",
                fg="white",
                font=("Helvetica", 12, "bold"),
                activebackground="#45a049",
                activeforeground="white",
                relief=tk.RAISED
            )
            verify_button.grid(row=0, column=0, padx=20)

            # Cancel button
            cancel_button = tk.Button(
                button_frame,
                text="Cancel",
                command=verify_window.destroy,
                bg="#F44336",
                fg="white",
                font=("Helvetica", 12, "bold"),
                activebackground="#e53935",
                activeforeground="white",
                relief=tk.RAISED
            )
            cancel_button.grid(row=0, column=1, padx=20)

            # Set focus on the Verify button and bind Enter key to trigger it
            verify_button.focus_set()
            verify_window.bind("<Return>", lambda event: verify_button.invoke())

        expose_button = tk.Button(
            edit_window,
            text="Expose",
            command=expose_password,
            bg="#FF9800",
            fg="white",
            font=("Helvetica", 10, "bold"),
            activebackground="#FFB74D",
            activeforeground="white",
            relief=tk.RAISED
        )
        expose_button.grid(row=1, column=2, padx=10, pady=10, sticky="w")

        # Target Name
        tk.Label(edit_window, text="Target Name:", font=("Helvetica", 12), bg="#e6f7ff").grid(row=2, column=0, padx=10,
                                                                                              pady=10, sticky="w")
        target_entry = ttk.Entry(edit_window, font=("Helvetica", 12), width=30)
        target_entry.insert(0, target_name)
        target_entry.grid(row=2, column=1, padx=10, pady=10)

        def save_changes():
            """
            Save changes made in the edit window to the database and refresh the table.
            """
            updated_account_id = account_id_entry.get().strip()
            updated_password = password_entry.get().strip()
            updated_target_name = target_entry.get().strip()

            # Dictionary to store updates
            updates = {}

            # Compare each field to its original value
            if updated_account_id != old_account_id:
                updates["account_id"] = updated_account_id
            if updated_target_name != target_name:
                updates["target_name"] = updated_target_name

            # Handle password field: check if it was exposed and updated
            if updated_password != "******":  # Ensure password is not left masked
                hashed_password = bcrypt.hashpw(updated_password.encode(), bcrypt.gensalt()).decode()
                updates["hashed_password"] = hashed_password
                updates["original_password"] = updated_password  # Update the original password if needed

            # Debugging: Check updates dictionary
            print("Updates dictionary:", updates)

            # If no fields were updated, show a message
            if not updates:
                messagebox.showinfo("No Changes", "No changes detected. Nothing was updated.", parent=edit_window)
                return

            # Update the record in the database
            try:
                conn = sqlite3.connect(SupplementClass.DB_NAME)
                cursor = conn.cursor()

                # Build the SQL query dynamically
                set_clause = ", ".join(f"{key} = ?" for key in updates.keys())
                sql = f"UPDATE passwords SET {set_clause} WHERE account_id = ? AND target_name = ?"
                params = list(updates.values()) + [old_account_id.strip(), target_name.strip()]

                # Debugging: Check SQL query and params
                print("SQL Query:", sql)
                print("Query Parameters:", params)

                cursor.execute(sql, params)

                # Debugging: Check how many rows were affected
                rows_affected = cursor.rowcount
                print(f"Rows affected: {rows_affected}")

                # Fetch the updated record for confirmation
                cursor.execute("SELECT * FROM passwords WHERE account_id = ? AND target_name = ?",
                               [updated_account_id.strip(), updated_target_name.strip()])
                updated_record = cursor.fetchone()
                print(f"Updated record: {updated_record}")  # Debug

                conn.commit()
                conn.close()

                if rows_affected == 0:
                    messagebox.showwarning("No Match", "No matching record was found. Update failed.",
                                           parent=edit_window)
                    return

                messagebox.showinfo("Success", "Record updated successfully.", parent=edit_window)
                self.refresh_table()  # Refresh the table to show updated records
                edit_window.destroy()
            except Exception as e:
                logging.error(f"Error updating record: {e}")
                messagebox.showerror("Error", "Failed to update the record. Check logs for details.",
                                     parent=edit_window)
            self.refresh_table()  # Refresh the table to show updated records

        # Cancel changes
        def cancel_edit():
            edit_window.destroy()

        # Buttons
        button_frame = tk.Frame(edit_window, bg="#e6f7ff")
        button_frame.grid(row=3, column=0, columnspan=3, pady=20)

        save_button = tk.Button(
            button_frame,
            text="Save",
            command=save_changes,
            bg="#4CAF50",
            fg="white",
            font=("Helvetica", 12, "bold"),
            activebackground="#45a049",
            activeforeground="white",
            relief=tk.RAISED
        )
        save_button.grid(row=0, column=0, padx=10)

        cancel_button = tk.Button(
            button_frame,
            text="Cancel",
            command=cancel_edit,
            bg="#F44336",
            fg="white",
            font=("Helvetica", 12, "bold"),
            activebackground="#e53935",
            activeforeground="white",
            relief=tk.RAISED
        )
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
        Includes larger input fields, vertical and horizontal scrollbars,
        a search field, right-click menu, copy functionality, and drag selection.
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

        # Account ID Entry
        tk.Label(input_frame, text="Account ID:", font=("Helvetica", 14), bg="#e6f7ff").grid(row=0, column=0, padx=15,
                                                                                             pady=10, sticky="e")
        self.account_id_entry = ttk.Entry(input_frame, font=("Helvetica", 14), justify="center", width=35)
        self.account_id_entry.grid(row=0, column=1, padx=15, pady=10, sticky="w")

        # Password Entry
        tk.Label(input_frame, text="Password:", font=("Helvetica", 14), bg="#e6f7ff").grid(row=1, column=0, padx=15,
                                                                                           pady=10, sticky="e")
        self.password_entry = ttk.Entry(input_frame, font=("Helvetica", 14), justify="center", width=35, show="*")
        self.password_entry.grid(row=1, column=1, padx=15, pady=10, sticky="w")

        # Target Name Entry
        tk.Label(input_frame, text="Target Name:", font=("Helvetica", 14), bg="#e6f7ff").grid(row=2, column=0, padx=15,
                                                                                              pady=10, sticky="e")
        self.target_entry = ttk.Entry(input_frame, font=("Helvetica", 14), justify="center", width=35)
        self.target_entry.grid(row=2, column=1, padx=15, pady=10, sticky="w")

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

        tk.Label(search_frame, text="Search:", font=("Helvetica", 14), bg="#e6f7ff").grid(row=0, column=0, padx=15,
                                                                                          pady=10)
        self.search_entry = tk.Entry(search_frame, font=("Helvetica", 14), width=35, bg="yellow", fg="blue",
                                     justify="center")
        self.search_entry.grid(row=0, column=1, padx=15, pady=10)
        self.search_entry.bind("<KeyRelease>", filter_table)

        # Configure grid styling and font
        style = ttk.Style()
        style.configure("Treeview", font=("Helvetica", 12), rowheight=30)  # Font size 14 for data rows
        style.configure("Treeview.Heading", font=("Helvetica", 14, "bold"))  # Font size 14 for column headers

        # Table Section
        table_frame = tk.Frame(self.root, bg="#e6f7ff")
        table_frame.pack(pady=10, fill=tk.BOTH, expand=True)

        # Table Columns
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
            selectmode="extended",
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
                rows = ["\t".join(self.table.item(item, "values")) for item in selected_items]
                self.root.clipboard_clear()
                self.root.clipboard_append("\n".join(rows))
                self.root.update()  # Update the clipboard
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
                self.table.selection_add(row_id)

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
            footer_frame, text="Total Records: 0", font=("Helvetica", 14), bg="#e6f7ff", anchor="center"
        )
        self.total_records_label.pack(pady=6)


        self.refresh_table()

        # Force refresh the root window
        self.root.update()


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

    def setup_menus(self):
        """
        Set up the Tool and Maintenance menus.
        """
        menu_bar = Menu(self.root)

        # Tools Menu
        tools_menu = Menu(menu_bar, tearoff=0)
        tools_menu.add_command(label="1__Reset Admin Password", command=SupplementClass.send_recovery_email)
        tools_menu.add_separator()
        tools_menu.add_command(label="2__Exit", command=self.root.destroy)  # Exits the program
        menu_bar.add_cascade(label="Tools", menu=tools_menu)

        # Maintenance Menu
        maintenance_menu = Menu(menu_bar, tearoff=0)
        maintenance_menu.add_command(label="1__Export data to Excel", command=self.export_to_excel)
        maintenance_menu.add_command(label="2__Upload data from Excel", command=self.upload_data)
        maintenance_menu.add_command(label="3__Reset Admin", command=self.reset_admin)
        maintenance_menu.add_command(label="4__Reset Email Sender", command=self.reset_email_sender)
        menu_bar.add_cascade(label="Maintenance", menu=maintenance_menu)


        # About Menu
        about_menu = Menu(menu_bar, tearoff=0)
        about_menu.add_command(label="1__About Us", command=self.show_about_window)
        menu_bar.add_cascade(label="About", menu=about_menu)

        self.root.config(menu=menu_bar)

        # Settings menu
        settings_menu = Menu(menu_bar, tearoff=0)
        settings_menu.add_command(label="1__Inactivity Timer", command=self.open_settings_window)
        menu_bar.add_cascade(label="Settings", menu=settings_menu)

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
        Export data to an encrypted .aes file and allow decryption back to Excel
        after verifying the admin password. Deletes the .aes file after successful export.
        """
        try:
            # Set the Downloads folder as the save location
            downloads_folder = os.path.expanduser("~/Downloads")
            if not os.path.exists(downloads_folder):
                os.makedirs(downloads_folder)

            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            aes_filename = os.path.join(downloads_folder, f"Exported_{timestamp}.aes")
            excel_filename = os.path.join(downloads_folder, f"Exported_{timestamp}.xlsx")

            # Fetch data from the database and rename columns to match the expected format
            conn = sqlite3.connect(SupplementClass.DB_NAME)
            query = "SELECT account_id, original_password, target_name FROM passwords"
            df = pd.read_sql_query(query, conn)
            conn.close()

            # Rename columns to match expected format
            column_mapping = {
                "account_id": "Account ID",
                "original_password": "Password",
                "target_name": "Target Name"
            }
            df.rename(columns=column_mapping, inplace=True)

            # Save data to an encrypted .aes file
            temp_excel_path = os.path.join(downloads_folder, f"temp_{timestamp}.xlsx")
            df.to_excel(temp_excel_path, index=False)

            admin_password = SupplementClass.get_admin_password("admin")
            pyAesCrypt.encryptFile(temp_excel_path, aes_filename, admin_password, BUFFER_SIZE)
            os.remove(temp_excel_path)

            # Create a fancy decryption window
            decrypt_window = Toplevel(self.root)
            decrypt_window.title("Decrypt and Export")
            decrypt_window.geometry("500x300")
            decrypt_window.configure(bg="#e6f7ff")  # Match the Password Manager's color theme
            decrypt_window.resizable(False, False)

            # Center the window
            decrypt_window.geometry(
                f"{500}x{300}+{self.root.winfo_x() + (self.root.winfo_width() // 2) - 250}+{self.root.winfo_y() + (self.root.winfo_height() // 2) - 150}"
            )

            # Title Label
            Label(
                decrypt_window,
                text="Decrypt and Export",
                font=("Helvetica", 16, "bold"),
                bg="#4682B4",
                fg="white",
                pady=10
            ).pack(fill="x")

            # Instruction Label
            Label(
                decrypt_window,
                text="Enter Admin Password to Decrypt and Export:",
                font=("Helvetica", 12),
                bg="#e6f7ff",
                fg="#333333"
            ).pack(pady=20)

            # Password Entry
            password_entry = ttk.Entry(decrypt_window, width=30, show="*")
            password_entry.pack(pady=10)

            # Button Frame
            button_frame = ttk.Frame(decrypt_window, style="TFrame")
            button_frame.pack(pady=20)

            def process_decryption():
                entered_password = password_entry.get().strip()
                if entered_password != admin_password:
                    messagebox.showerror("Error", "Incorrect Admin Password!", parent=decrypt_window)
                    return

                try:
                    # Decrypt the .aes file to an Excel file
                    pyAesCrypt.decryptFile(aes_filename, excel_filename, admin_password, BUFFER_SIZE)

                    # Immediately delete the .aes file after decryption
                    os.remove(aes_filename)

                    # Notify the user of success
                    messagebox.showinfo("Success", f"Data successfully exported to {excel_filename}!", parent=self.root)
                    decrypt_window.destroy()
                except Exception as e:
                    logging.error(f"Failed to decrypt the file: {e}")
                    messagebox.showerror("Error", f"Failed to decrypt the file: {e}", parent=decrypt_window)

            def cancel_decryption():
                """Close the decryption window without processing."""
                decrypt_window.destroy()

            # OK Button
            ok_button = Button(
                button_frame,
                text="OK",
                command=process_decryption,
                font=("Helvetica", 12, "bold"),
                bg="#4CAF50",
                fg="white",
                activebackground="#45a049",
                activeforeground="white",
                relief="raised",
                width=10
            )
            ok_button.grid(row=0, column=0, padx=10)
            ok_button.focus_set()  # Set focus to the OK button

            # Cancel Button
            cancel_button = Button(
                button_frame,
                text="Cancel",
                command=cancel_decryption,
                font=("Helvetica", 12, "bold"),
                bg="#F44336",
                fg="white",
                activebackground="#e53935",
                activeforeground="white",
                relief="raised",
                width=10
            )
            cancel_button.grid(row=0, column=1, padx=10)

            # Bind the Enter key to the OK button
            decrypt_window.bind("<Return>", lambda event: process_decryption())

        except Exception as e:
            logging.error(f"Failed during export: {e}")
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

    def open_settings_window(self):
        """
        Open a settings window to adjust the inactivity timeout.
        """
        # Create the settings window
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("400x200")
        settings_window.configure(bg="#e6f7ff")
        settings_window.transient(self.root)
        settings_window.grab_set()

        # Center the settings window relative to the Password Manager window
        self.center_window(settings_window, 400, 200)

        # Label for inactivity timeout
        tk.Label(
            settings_window,
            text="Set Inactivity Timeout (in minutes):",
            font=("Helvetica", 12),
            bg="#e6f7ff"
        ).grid(row=0, column=0, padx=20, pady=20, sticky="w")

        # Fetch current timeout value
        current_timeout = self.inactivity_timeout // 60  # Convert seconds to minutes
        timeout_var = tk.StringVar(value=str(current_timeout))

        # Entry for timeout
        timeout_entry = ttk.Entry(settings_window, textvariable=timeout_var, width=10)
        timeout_entry.grid(row=0, column=1, padx=20, pady=20, sticky="w")

        # Button frame for Save and Cancel
        button_frame = tk.Frame(settings_window, bg="#e6f7ff")
        button_frame.grid(row=1, column=0, columnspan=2, pady=20)

        # Save button
        def save_timeout():
            try:
                # Update the inactivity timeout
                timeout = int(timeout_var.get())
                self.inactivity_timeout = timeout * 60  # Convert minutes to seconds

                # Provide feedback and close the window
                messagebox.showinfo("Settings Updated", f"Inactivity timeout set to {timeout} minutes.",
                                    parent=settings_window)
                settings_window.destroy()
            except ValueError:
                messagebox.showerror("Invalid Input", "Please enter a valid number.", parent=settings_window)

        save_button = tk.Button(
            button_frame,
            text="Save",
            command=save_timeout,
            bg="#4CAF50",
            fg="white",
            font=("Helvetica", 12, "bold"),
            relief=tk.RAISED
        )
        save_button.pack(side="left", padx=10)

        # Cancel button
        cancel_button = tk.Button(
            button_frame,
            text="Cancel",
            command=settings_window.destroy,
            bg="#F44336",
            fg="white",
            font=("Helvetica", 12, "bold"),
            relief=tk.RAISED
        )
        cancel_button.pack(side="left", padx=10)

    def save_inactivity_timeout(self, timeout):
        """
        Save the inactivity timeout value to the database.
        """
        conn = sqlite3.connect(SupplementClass.DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE app_settings SET value = ? WHERE key = 'inactivity_timeout'
        """, (str(timeout),))  # Convert to string for storage
        conn.commit()
        conn.close()

    def reset_inactivity_timer(self, event=None):
        """Reset the inactivity timer."""
        self.last_activity_time = time.time()

    def initialize_settings_table(self):
        """
        Ensure the settings table exists in the database.
        """
        conn = sqlite3.connect(SupplementClass.DB_NAME)
        cursor = conn.cursor()

        # Create the settings table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        # Insert default inactivity timeout if not present
        cursor.execute("""
            INSERT OR IGNORE INTO app_settings (key, value)
            VALUES ('inactivity_timeout', '600000')  -- Default 10 minutes in milliseconds
        """)
        conn.commit()
        conn.close()

    def inactivity_time(self, last_activity_time, timeout_duration):
        """
        Calculate the time elapsed since the last activity and determine if the timeout has occurred.

        Args:
            last_activity_time (float): The timestamp of the last user activity.
            timeout_duration (int): The inactivity timeout duration in seconds.

        Returns:
            bool: True if the timeout has occurred, False otherwise.
            int: The remaining time (in seconds) before the timeout.
        """
        current_time = time.time()
        elapsed_time = current_time - last_activity_time
        remaining_time = timeout_duration - elapsed_time

        if elapsed_time >= timeout_duration:
            return True, 0  # Timeout occurred
        else:
            return False, int(remaining_time)

    def log_off(self):
        """Handle logging off the user."""
        messagebox.showinfo("Session Timeout", "You have been logged off due to inactivity.")
        self.authenticate_admin()  # Redirect to the admin authentication window

    def setup_inactivity_tracker(self):
        """
        Sets up a global inactivity tracker that redirects to admin authentication after inactivity.
        """
        self.warning_popup_active = False

        # Fetch timeout in minutes and convert to seconds
        self.inactivity_time = SupplementClass.fetch_inactivity_timeout() * 60
        self.warning_time = 60  # 1-minute warning time in seconds
        self.last_activity = time.time()

        def reset_timer(event=None):
            """Reset the inactivity timer on user interaction."""
            self.last_activity = time.time()
            if self.warning_popup_active:
                self.warning_popup_active = False
            logging.info("Inactivity timer reset.")

        def show_warning_popup():
            """Show a warning popup 1 minute before session expiration."""
            if self.warning_popup_active:
                return  # Avoid multiple popups

            self.warning_popup_active = True
            warning_popup = tk.Toplevel(self.root)
            warning_popup.title("Inactivity Warning")
            warning_popup.geometry("400x200")
            self.center_window(warning_popup)
            warning_popup.configure(bg="#e6f7ff")
            warning_popup.transient(self.root)
            warning_popup.grab_set()

            tk.Label(
                warning_popup,
                text="You will be logged out in 1 minute due to inactivity.",
                font=("Helvetica", 12),
                bg="#e6f7ff"
            ).pack(pady=20)

            def continue_logged_in():
                """Reset the timer and close the popup."""
                self.last_activity = time.time()
                self.warning_popup_active = False
                warning_popup.destroy()

            def allow_logout():
                """Trigger session expiration."""
                self.warning_popup_active = False
                warning_popup.destroy()
                redirect_to_admin_authentication()

            tk.Button(
                warning_popup,
                text="Continue Logged In",
                command=continue_logged_in,
                bg="#4CAF50",
                fg="white",
                font=("Helvetica", 12, "bold")
            ).pack(pady=10)

            tk.Button(
                warning_popup,
                text="OK (Expire)",
                command=allow_logout,
                bg="#F44336",
                fg="white",
                font=("Helvetica", 12, "bold")
            ).pack(pady=5)

        def redirect_to_admin_authentication():
            """Redirect to Admin Authentication upon session expiration."""
            logging.info("Session expired. Redirecting to Admin Authentication...")
            messagebox.showinfo("Session Expired", "Your session has expired. Please log in again.")
            self.authenticate_admin()  # Bring the admin login window

        def check_inactivity():
            """
            Checks for user inactivity and handles warning popup or session expiration.
            """
            elapsed_time = time.time() - self.last_activity
            logging.info(f"Elapsed time since last activity: {elapsed_time} seconds")

            current_time = time.time()
            if current_time - self.last_activity_time > self.inactivity_time:
                self.log_off()
            else:
                self.root.after(1000, self.check_inactivity)  # Check every second


            if self.inactivity_checker_active:
                return  # Prevent multiple concurrent timers
            self.inactivity_checker_active = True

            # Show warning popup 1 minute before logout
            if elapsed_time >= (self.inactivity_time - self.warning_time) and not self.warning_popup_active:
                show_warning_popup()

            # Redirect to authentication if inactivity timeout is reached
            if elapsed_time >= self.inactivity_time:
                if self.warning_popup_active:
                    self.warning_popup_active = False
                redirect_to_admin_authentication()
            else:
                self.root.after(1000, check_inactivity)  # Check every second
            self.inactivity_checker_active = False

        # Bind user events to reset the timer
        self.root.bind_all("<Any-KeyPress>", reset_timer)
        self.root.bind_all("<Any-Button>", reset_timer)
        self.root.bind_all("<Motion>", reset_timer)

        logging.info("Inactivity tracker started.")
        check_inactivity()

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


