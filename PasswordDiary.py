import tkinter as tk
from tkinter import messagebox
import bcrypt
import pyotp
import sqlite3
from tkinter import ttk
from cryptography.fernet import Fernet
import pyperclip
import datetime
from tkinter import simpledialog
import webbrowser

# Load the previously saved key
with open('fernet_key.txt', 'rb') as file:
    key = file.read()

cipher_suite = Fernet(key)

def encrypt_password(password):
    """Encrypt the password."""
    if isinstance(password, str):
        password = password.encode()  # Convert to bytes
    encrypted_password = cipher_suite.encrypt(password)
    return encrypted_password

def decrypt_password(encrypted_password):
    """Decrypt the password."""
    decrypted_password = cipher_suite.decrypt(encrypted_password).decode()  # Convert to stringf
    return decrypted_password

secret = None  # Make secret a global variable

def register():
    global secret  # Make the secret variable global so it can be accessed in other functions
    username = username_entry.get()
    password = password_entry.get()

    # Connect to the database
    conn = sqlite3.connect('password_diary.db')
    c = conn.cursor()

    # Check if the username already exists
    c.execute("SELECT username FROM users WHERE username=?", (username,))
    if c.fetchone():
        messagebox.showerror("Registration Error", "Username already exists")
        return

    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    # Check if the password contains at least one uppercase letter and numbers
    if not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
        messagebox.showerror("Registration error", "Password must contain at least one uppercase letter and numbers")
        return

    # Create table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY,
                  password TEXT NOT NULL,
                  secret TEXT)''')

    # Generate a new secret for each user
    secret = pyotp.random_base32()

    # Insert user into the table
    try:
        c.execute("INSERT INTO users (username, password, secret) VALUES (?,?,?)", (username, hashed_password, secret))
    except sqlite3.IntegrityError:
        messagebox.showerror("Registration Error", "Username already exists")
        return
    conn.commit()

    # Display the secret key in a new window
    display_secret_key(secret)

def login():
    global secret  # Make the secret variable global so it can be accessed in other functions
    username = username_entry.get()
    password = password_entry.get().encode()

    # Connect to the database
    conn = sqlite3.connect('password_diary.db')
    c = conn.cursor()

    # Check if the user exists
    c.execute("SELECT password, secret FROM users WHERE username=?", (username,))
    user = c.fetchone()

    if user:
        stored_password, secret = user
        if bcrypt.checkpw(password, stored_password):
            totp = pyotp.TOTP(secret)
            otp = otp_entry.get()

            if totp.verify(otp):
                messagebox.showinfo("Login", "Login Successful")
                root.destroy()  # Close the main window
                display_dashboard_with_roles()  # Navigate to the next screen
            else:
                messagebox.showerror("Login Error", "Invalid OTP")
        else:
            messagebox.showerror("Login Error", "Incorrect password")
    else:
        messagebox.showerror("Login Error", "User not found")

def display_secret_key(secret):
    # Display the secret key in a new window
    qr_window = tk.Tk()
    qr_window.title("The Secret Key")
    qr_window.geometry("600x300")

    secret_label = tk.Label(qr_window, text=f"Secret key: {secret}", font=("Arial", 14))
    secret_label.pack(pady=20)

    # Copy the secret key to the clipboard
    pyperclip.copy(secret)

    # Optional: Display a message that the secret key has been copied to the clipboard
    copied_label = tk.Label(qr_window, text="Secret key copied to clipboard!", font=("Arial", 10))
    copied_label.pack(pady=10)

def display_dashboard_with_roles():
    dashboard_window = tk.Tk()
    dashboard_window.geometry("300x200")
    dashboard_window.title("HOME")
    dashboard_window.configure(bg="#333333")

    admin_button = tk.Button(dashboard_window, text="Admin", command=lambda: show_role("Admin", dashboard_window), bg="#555555", fg="#FFDF00")
    admin_button.pack(pady=10)

    user_button = tk.Button(dashboard_window, text="User", command=lambda: show_role("User", dashboard_window), bg="#555555", fg="#FFDF00")
    user_button.pack(pady=10)

    dashboard_window.mainloop()

def display_user_dashboard():
    dashboard_window = tk.Tk()
    dashboard_window.geometry("600x400")  
    dashboard_window.title("User Dashboard")
    dashboard_window.configure(bg="#333333")

    # Define refresh_list here so it's accessible throughout display_user_dashboard
    def refresh_list():
        for i in tree.get_children():
            tree.delete(i)
        conn = sqlite3.connect('password_diary.db')
        c = conn.cursor()
        c.execute("SELECT website, username, date FROM user_dashboard_entries")
        for row in c.fetchall():
            tree.insert('', tk.END, values=(row[0], row[1], row[2]))
        conn.close()

    # Frame for entry fields (Moved above the table as requested)
    entry_fields_frame = tk.Frame(dashboard_window, bg="#333333")
    entry_fields_frame.pack(side=tk.TOP, fill=tk.X, pady=10, expand=True)

    # Frame for buttons
    buttons_frame = tk.Frame(dashboard_window, bg="#333333")
    buttons_frame.pack(side=tk.TOP, fill=tk.X)

    # Frame for the table
    table_frame = tk.Frame(dashboard_window, relief=tk.SUNKEN, borderwidth=1, bg="#333333")
    table_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

    # Entry fields for new record (Placed in the entry_fields_frame)
    tk.Label(entry_fields_frame, text="Website Name", bg="#333333", fg="#FFDF00").pack(anchor="center")
    website_entry = tk.Entry(entry_fields_frame, bg="#555555", fg="#FFDF00", insertbackground="#FFDF00")
    website_entry.pack(anchor="center")

    tk.Label(entry_fields_frame, text="Username", bg="#333333", fg="#FFDF00").pack(anchor="center")
    username_entry = tk.Entry(entry_fields_frame, bg="#555555", fg="#FFDF00", insertbackground="#FFDF00")
    username_entry.pack(anchor="center")

    tk.Label(entry_fields_frame, text="Password", bg="#333333", fg="#FFDF00").pack(anchor="center")
    password_entry = tk.Entry(entry_fields_frame, bg="#555555", fg="#FFDF00", insertbackground="#FFDF00")
    password_entry.pack(anchor="center")

    # Function to insert a new entry
    def insert_entry():
        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get()
        date = datetime.datetime.now().strftime('%Y-%m-%d')  # Automatically record the current date

        # Encrypt the password before storing
        encrypted_password = encrypt_password(password)

        conn = sqlite3.connect('password_diary.db')
        c = conn.cursor()
        # Ensure the encrypted_password is correctly formatted for insertion
        c.execute("INSERT INTO user_dashboard_entries (website, username, password, date) VALUES (?, ?, ?, ?)",
                  (website, username, encrypted_password.decode('utf-8'), date))  # Assuming encrypted_password is bytes
        conn.commit()
        conn.close()

        # Refresh the list and clear the entry fields
        refresh_list()
        website_entry.delete(0, tk.END)
        username_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)

    # Button to add a new entry
    tk.Button(buttons_frame, text="Add Entry", command=insert_entry, bg="#555555", fg="#FFDF00").pack(side=tk.RIGHT)

    # Function to reset the entry fields
    def reset_fields():
        website_entry.delete(0, tk.END)
        username_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)

    # Button to reset the entry fields
    tk.Button(buttons_frame, text="Reset", command=reset_fields, bg="#555555", fg="#FFDF00").pack(side=tk.RIGHT)

    # Function to exit the admin dashboard
    def exit_dashboard():
        dashboard_window.destroy()
        display_dashboard_with_roles()

    # Button to exit the admin dashboard
    tk.Button(buttons_frame, text="Exit", command=exit_dashboard, bg="#555555", fg="#FFDF00").pack(side=tk.LEFT)

    # Treeview for the entries list
    columns = ('website', 'username', 'date')
    tree = ttk.Treeview(table_frame, columns=columns, show='headings')
    tree.heading('website', text='Website Name')
    tree.heading('username', text='Username')
    tree.heading('date', text='Date')
    tree.pack(side=tk.LEFT, expand=True, fill='both')

    scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
    scrollbar.pack(side=tk.RIGHT, fill='y')
    tree.configure(yscrollcommand=scrollbar.set)

    # Function to handle double-click on an entry
    def on_item_double_click(event):
        selected_items = tree.selection()  # Get selected items
        if selected_items:  # Check if there is at least one selected item
            item = selected_items[0]  # Get the first selected item
            website, username = tree.item(item, 'values')[0], tree.item(item, 'values')[1]
            conn = sqlite3.connect('password_diary.db')
            c = conn.cursor()
            c.execute("SELECT password FROM user_dashboard_entries WHERE website=? AND username=?", (website, username))
            encrypted_password = c.fetchone()[0]
            conn.close()

            # Decrypt the password before displaying it
            password = decrypt_password(encrypted_password)
            # Copy username and password to clipboard
            clipboard_content = f"{password}"
            pyperclip.copy(clipboard_content)
            messagebox.showinfo("Entry Details", f"Username: {username}\nPassword: {password}\n\n(Password copied to clipboard)")
        else:
            messagebox.showwarning("Selection Error", "Please select an item first.")

    tree.bind("<Double-1>", on_item_double_click)

    # Create a context menu
    context_menu = tk.Menu(dashboard_window, tearoff=0)
    context_menu.add_command(label="Delete", command=lambda: delete_entry(tree))

    # Function to handle right-click on an entry
    def on_right_click(event):
        # Display the context menu at the position of the mouse right-click
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            # Make sure the menu is closed
            context_menu.grab_release()

    tree.bind("<Button-3>", on_right_click)  # Use "<Button-2>" if you're on macOS

    # Function to delete an entry
    def delete_entry(tree):
        selected_item = tree.selection()[0]
        website, username, _ = tree.item(selected_item, 'values')
        # Perform deletion from the user_dashboard_entries table
        conn = sqlite3.connect('password_diary.db')
        c = conn.cursor()
        c.execute("DELETE FROM user_dashboard_entries WHERE website=? AND username=?", (website, username))
        conn.commit()
        conn.close()
        # Remove the item from the treeview
        tree.delete(selected_item)
        print(f"Deleted {website}, {username}")  # Placeholder action

    # Initial list refresh
    refresh_list()

    dashboard_window.mainloop()

def show_role(role, dashboard_window):
    dashboard_window.destroy()  # Close the roles dashboard window
    if role == "Admin":
        display_admin_login()
    elif role == "User":
        display_user_dashboard()  # Display the user dashboard for regular users
    else:
        messagebox.showinfo("Role", f"You have selected the {role} role.")

admin_username = "admin"
admin_password = "PMT24"  # Admin Password
hashed_admin_password = bcrypt.hashpw(admin_password.encode(), bcrypt.gensalt())
print("Hashed admin password (store this securely):", hashed_admin_password)

def display_admin_login():
    admin_login_window = tk.Tk()
    admin_login_window.geometry("250x200")
    admin_login_window.title("Admin Login")
    admin_login_window.configure(bg="#333333")  # Set background color for dark theme

    tk.Label(admin_login_window, text="Username", bg="#333333", fg="#FFDF00").grid(row=0, column=0, padx=10, pady=10)  # Adjust label colors for dark theme
    admin_username_entry = tk.Entry(admin_login_window, bg="#555555", fg="#FFDF00", insertbackground="#FFDF00")  # Adjust entry colors for dark theme
    admin_username_entry.grid(row=0, column=1, padx=10, pady=10)

    tk.Label(admin_login_window, text="Password", bg="#333333", fg="#FFDF00").grid(row=1, column=0, padx=10, pady=10)  # Adjust label colors for dark theme
    admin_password_entry = tk.Entry(admin_login_window, show="*", bg="#555555", fg="#FFDF00", insertbackground="#FFDF00")  # Adjust entry colors for dark theme
    admin_password_entry.grid(row=1, column=1, padx=10, pady=10)

    tk.Button(admin_login_window, text="Login", command=lambda: verify_admin_login(admin_username_entry.get(), admin_password_entry.get(), admin_login_window), bg="#555555", fg="#FFDF00").grid(row=2, column=0, columnspan=2, padx=10, pady=10)  # Adjust button colors for dark theme

# Function to exit the admin dashboard
    def exit_dashboard():
        admin_login_window.destroy()
        display_dashboard_with_roles()

    # Button to exit the admin dashboard
    tk.Button(admin_login_window, text="Exit", command=exit_dashboard, bg="#555555", fg="#FFDF00").grid(row=3, column=0, columnspan=2, padx=10, pady=10)  # Adjust button colors for dark theme

    admin_login_window.mainloop()

def verify_admin_login(username, password, admin_login_window):
    if username == admin_username and bcrypt.checkpw(password.encode(), hashed_admin_password):
        messagebox.showinfo("Admin Login", "Login Successful")
        admin_login_window.destroy()  # Close the admin login window
        display_admin_dashboard()  # Display the admin dashboard
    else:
        messagebox.showerror("Admin Login", "Incorrect username or password")

def display_admin_dashboard():
    dashboard_window = tk.Tk()
    dashboard_window.geometry("600x400") 
    dashboard_window.title("Admin Dashboard")
    dashboard_window.configure(bg="#333333")

    # Frame for the table
    table_frame = tk.Frame(dashboard_window, bg="#333333")
    table_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False)  

    # Frame for the form
    form_frame = tk.Frame(dashboard_window, bg="#333333")
    form_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)  

    # Frame for form fields
    form_fields_frame = tk.Frame(form_frame, bg="#333333")
    form_fields_frame.pack(side=tk.TOP, padx=10, pady=10)

    # Frame for buttons
    buttons_frame = tk.Frame(form_frame, bg="#333333")
    buttons_frame.pack(side=tk.TOP, padx=10, pady=10)

    # Treeview for the entries list
    columns = ('website', 'username', 'date')
    tree = ttk.Treeview(table_frame, columns=columns, show='headings')
    tree.heading('website', text='Website Name')
    tree.heading('username', text='Username')
    tree.heading('date', text='Date')

    # Set column width to prevent stretching
    tree.column('website', width=120)
    tree.column('username', width=120)
    tree.column('date', width=120)

    tree.pack(side=tk.LEFT, fill='both', expand=True)  # Adjust packing to fill both directions

    # Add a scrollbar
    scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=tree.yview)
    tree.configure(yscroll=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill='y')

    # Entry fields for new record
    tk.Label(form_fields_frame, text="Website Name", bg="#333333", fg="#FFDF00").pack()
    website_entry = tk.Entry(form_fields_frame, bg="#555555", fg="#FFDF00", insertbackground="#FFDF00")
    website_entry.pack()

    tk.Label(form_fields_frame, text="Username", bg="#333333", fg="#FFDF00").pack()
    username_entry = tk.Entry(form_fields_frame, bg="#555555", fg="#FFDF00", insertbackground="#FFDF00")
    username_entry.pack()

    tk.Label(form_fields_frame, text="Password", bg="#333333", fg="#FFDF00").pack()
    password_entry = tk.Entry(form_fields_frame, bg="#555555", fg="#FFDF00", insertbackground="#FFDF00")
    password_entry.pack()

    tk.Label(form_fields_frame, text="URL", bg="#333333", fg="#FFDF00").pack()
    url_entry = tk.Entry(form_fields_frame, bg="#555555", fg="#FFDF00", insertbackground="#FFDF00")
    url_entry.pack()

    # Function to insert a new entry
    def insert_entry():
        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get()
        url = url_entry.get()  # Get the URL from the entry
        current_date = datetime.datetime.now().strftime('%Y-%m-%d')

        encrypted_password = encrypt_password(password)

        conn = sqlite3.connect('password_diary.db')
        c = conn.cursor()
        c.execute("INSERT INTO password_entries (website, username, password, date, last_update_date, url) VALUES (?, ?, ?, ?, ?, ?)",
                  (website, username, encrypted_password, current_date, current_date, url))
        conn.commit()
        conn.close()

        website_entry.delete(0, tk.END)
        username_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)
        url_entry.delete(0, tk.END)
        refresh_list()

    # Button to add a new entry
    tk.Button(buttons_frame, text="Confirm", command=insert_entry, bg="#555555", fg="#FFDF00").pack(anchor="center")

    # Function to reset the entry fields
    def reset_fields():
        website_entry.delete(0, tk.END)
        username_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)
        url_entry.delete(0, tk.END)

    # Button to reset the entry fields
    tk.Button(buttons_frame, text="Reset", command=reset_fields, bg="#555555", fg="#FFDF00").pack(anchor="center")

    # Function to confirm edit
    def confirm_edit():
        # Placeholder for confirm edit logic
        print("Confirm edit logic goes here")

    # Function to show users list
    def show_users():
        users_window = tk.Tk()
        users_window.geometry("400x300")
        users_window.title("Registered Users")
        users_window.configure(bg="#333333")

        users_tree = ttk.Treeview(users_window, columns=('Username'), show='headings')
        users_tree.heading('Username', text='Username')
        users_tree.pack(expand=True, fill='both')

        # Populate the treeview with usernames who have a secret key
        conn = sqlite3.connect('password_diary.db')
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE secret IS NOT NULL")
        for row in c.fetchall():
            users_tree.insert('', tk.END, values=(row[0]))
        conn.close()

        def delete_user():
            selected_item = users_tree.selection()[0]
            username = users_tree.item(selected_item, 'values')[0]
            # Delete user from the database
            conn = sqlite3.connect('password_diary.db')
            c = conn.cursor()
            c.execute("DELETE FROM users WHERE username=?", (username,))
            c.execute("DELETE FROM password_entries WHERE username=?", (username,))  # to delete user data 
            conn.commit()
            conn.close()
            users_tree.delete(selected_item)

        # Right-click menu
        users_menu = tk.Menu(users_window, tearoff=0)
        users_menu.add_command(label="Delete User", command=delete_user)

        def on_user_right_click(event):
            try:
                users_menu.tk_popup(event.x_root, event.y_root)
            finally:
                users_menu.grab_release()

        users_tree.bind("<Button-3>", on_user_right_click)

    # Button to show users list
    tk.Button(buttons_frame, text="Users List", command=show_users, bg="#555555", fg="#FFDF00").pack(anchor="center")

    # Function to exit the admin dashboard
    def exit_dashboard():
        dashboard_window.destroy()
        display_dashboard_with_roles()

    # Button to exit the admin dashboard
    tk.Button(buttons_frame, text="Exit", command=exit_dashboard, bg="#555555", fg="#FFDF00").pack(anchor="center")

    # Function to handle double-click on an entry
    def on_item_double_click(event):
        selected_items = tree.selection()  # Get selected items
        if selected_items:  # Check if there is at least one selected item
            item = selected_items[0]  # Get the first selected item
            website, username = tree.item(item, 'values')[0], tree.item(item, 'values')[1]
            conn = sqlite3.connect('password_diary.db')
            c = conn.cursor()
            c.execute("SELECT password FROM password_entries WHERE website=? AND username=?", (website, username))
            encrypted_password = c.fetchone()[0]
            conn.close()

            # Decrypt the password before displaying it
            password = decrypt_password(encrypted_password)
            # Copy username and password to clipboard
            clipboard_content = f"{password}"
            pyperclip.copy(clipboard_content)
            messagebox.showinfo("Entry Details", f"Username: {username}\nPassword: {password}\n\n(Password copied to clipboard)")
        else:
            messagebox.showwarning("Selection Error", "Please select an item first.")

    tree.bind("<Double-1>", on_item_double_click)

    # Create a context menu
    context_menu = tk.Menu(dashboard_window, tearoff=0)
    context_menu.add_command(label="Delete", command=lambda: delete_entry(tree))
    context_menu.add_command(label="Days Until Password Change", command=lambda: days_until_password_change_action(tree))
    context_menu.add_command(label="Reset Username", command=lambda: reset_username(tree, refresh_list))
    context_menu.add_command(label="Reset Password", command=lambda: reset_password(tree, refresh_list))
    context_menu.add_command(label="Launch URL", command=lambda: launch_url(tree))

    # Function to handle right-click on an entry
    def on_right_click(event):
        # Display the context menu at the position of the mouse right-click
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            # Make sure the menu is closed
            context_menu.grab_release()

    tree.bind("<Button-3>", on_right_click)  # Use "<Button-2>" if you're on macOS

    # Function to reset username for an entry
    def reset_username(tree, refresh_list):
        selected_item = tree.selection()[0]
        website, username, _ = tree.item(selected_item, 'values')

        # Prompt user for new username
        new_username = simpledialog.askstring("Reset Username", "Enter new username:", parent=dashboard_window)

        if new_username:
            # Update the entry in the database
            conn = sqlite3.connect('password_diary.db')
            c = conn.cursor()
            c.execute("UPDATE password_entries SET username=? WHERE website=? AND username=?", 
                      (new_username, website, username))
            conn.commit()
            conn.close()

            messagebox.showinfo("Reset Username", "Username updated successfully.")
            refresh_list()  # Refresh the table view
        else:
            messagebox.showerror("Reset Username", "Operation cancelled or invalid input.")

    # Function to reset password for an entry
    def reset_password(tree, refresh_list):
        selected_item = tree.selection()[0]
        website, username, _ = tree.item(selected_item, 'values')

        # Prompt user for new password
        new_password = simpledialog.askstring("Reset Password", "Enter new password:", parent=dashboard_window, show='*')

        if new_password:
            # Encrypt the new password before storing
            encrypted_new_password = encrypt_password(new_password)

            # Update the entry in the database
            conn = sqlite3.connect('password_diary.db')
            c = conn.cursor()
            c.execute("UPDATE password_entries SET password=? WHERE website=? AND username=?", 
                      (encrypted_new_password, website, username))
            conn.commit()
            conn.close()

            messagebox.showinfo("Reset Password", "Password updated successfully.")
            refresh_list()  # Refresh the table view
        else:
            messagebox.showerror("Reset Password", "Operation cancelled or invalid input.")

    # Function to delete an entry
    def delete_entry(tree):
        selected_item = tree.selection()[0]
        website, username, _ = tree.item(selected_item, 'values')
        # Perform deletion from the database
        conn = sqlite3.connect('password_diary.db')
        c = conn.cursor()
        c.execute("DELETE FROM password_entries WHERE website=? AND username=?", (website, username))
        conn.commit()
        conn.close()
        # Remove the item from the treeview
        tree.delete(selected_item)
        print(f"Deleted {website}, {username}")  # Placeholder action

    def launch_url(tree):
        selected_item = tree.selection()[0]  # Get the selected item
        if not selected_item:  # Check if an item is actually selected
            messagebox.showerror("Error", "Please select an entry first.")
            return

        website, username = tree.item(selected_item, 'values')[0:2]
        conn = sqlite3.connect('password_diary.db')
        c = conn.cursor()
        # Adjust the query below if your column names are different
        c.execute("SELECT url FROM password_entries WHERE website=? AND username=?", (website, username))
        result = c.fetchone()
        conn.close()

        if result and result[0]:
            webbrowser.open(result[0])  # Open the URL in the default web browser
        else:
            messagebox.showerror("Error", "URL not found for the selected entry.")

   
    # Function to refresh the entries list
    def refresh_list():
        for i in tree.get_children():
            tree.delete(i)
        conn = sqlite3.connect('password_diary.db')
        c = conn.cursor()
        c.execute("SELECT website, username, last_update_date FROM password_entries")  # Changed 'date' to 'last_update_date'
        for row in c.fetchall():
            tree.insert('', tk.END, values=(row[0], row[1], row[2]))  # Changed to display last_update_date in the tree view
        conn.close()

    # Initial list refresh
    refresh_list()

    check_passwords_to_update()

    dashboard_window.mainloop()

def check_passwords_to_update():
    conn = sqlite3.connect('password_diary.db')
    c = conn.cursor()
    c.execute("SELECT id, website, username, last_update_date FROM password_entries")
    rows = c.fetchall()
    conn.close()

    for row in rows:
        last_update_date = datetime.datetime.strptime(row[3], '%Y-%m-%d')
        if (datetime.datetime.now() - last_update_date).days >= 90:  # 90 days for 3 months
            print(f"Password for {row[2]} on {row[1]} needs to be updated. Last updated on {row[3]}")
            # implement the notification logic

def update_password_entries_table_with_url():
    conn = sqlite3.connect('password_diary.db')
    c = conn.cursor()
    try:
        c.execute('''ALTER TABLE password_entries ADD COLUMN url TEXT''')
    except sqlite3.OperationalError as e:
        if "duplicate column name" not in str(e):
            raise
    conn.commit()
    conn.close()

# Call the function to update the table
update_password_entries_table_with_url()

def days_until_password_change(website, username):
    conn = sqlite3.connect('password_diary.db')
    c = conn.cursor()
    c.execute("SELECT last_update_date FROM password_entries WHERE website=? AND username=?", (website, username))
    result = c.fetchone()
    conn.close()

    if result:
        last_update_date = datetime.datetime.strptime(result[0], '%Y-%m-%d')
        days_passed = (datetime.datetime.now() - last_update_date).days
        days_left = 90 - days_passed  # password needs to be changed every 90 days
        messagebox.showinfo("Password Change Reminder", f"{days_left} days left to change the password for {website}.")
    else:
        messagebox.showerror("Error", "Could not find the last update date for the selected entry.")

def days_until_password_change_action(tree):
    selected_item = tree.selection()[0]
    website, username = tree.item(selected_item, 'values')[0], tree.item(selected_item, 'values')[1]
    days_until_password_change(website, username)

def create_password_entries_table():
    conn = sqlite3.connect('password_diary.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS password_entries
                 (id INTEGER PRIMARY KEY,
                  website TEXT NOT NULL,
                  username TEXT NOT NULL,
                  password TEXT NOT NULL,
                  date TEXT NOT NULL)''')
    conn.commit()
    conn.close()

create_password_entries_table()

def user_dashboard_entries_table():
    conn = sqlite3.connect('password_diary.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS user_dashboard_entries
                 (id INTEGER PRIMARY KEY,
                  website TEXT NOT NULL,
                  username TEXT NOT NULL,
                  password TEXT NOT NULL,
                  date TEXT NOT NULL)''')
    conn.commit()
    conn.close()

user_dashboard_entries_table()

root = tk.Tk()
root.geometry("250x250")
root.title("Password Diary")
root.configure(bg="#333333")

username_label = tk.Label(root, text="Username", bg="#333333", fg="#FFDF00")
username_label.grid(row=0, column=0, padx=10, pady=10)
username_entry = tk.Entry(root, bg="#555555", fg="#FFDF00", insertbackground="#FFDF00")
username_entry.grid(row=0, column=1, padx=10, pady=10)

password_label = tk.Label(root, text="Password", bg="#333333", fg="#FFDF00")
password_label.grid(row=1, column=0, padx=10, pady=10)
password_entry = tk.Entry(root, show="*", bg="#555555", fg="#FFDF00", insertbackground="#FFDF00")
password_entry.grid(row=1, column=1, padx=10, pady=10)

otp_label = tk.Label(root, text="OTP", bg="#333333", fg="#FFDF00")
otp_label.grid(row=2, column=0, padx=10, pady=10)
otp_entry = tk.Entry(root, bg="#555555", fg="#FFDF00", insertbackground="#FFDF00")
otp_entry.grid(row=2, column=1, padx=10, pady=10)

register_button = tk.Button(root, text="Register", command=register, bg="#555555", fg="#FFDF00")
register_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

login_button = tk.Button(root, text="Login", command=login, bg="#555555", fg="#FFDF00")
login_button.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

root.mainloop()

