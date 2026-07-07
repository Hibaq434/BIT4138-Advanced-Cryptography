"""
app.py — Secure University Messenger (Tkinter front end)
==========================================================
Run with:  python3 app.py

Requires: Python 3.8+, tkinter (usually bundled with Python; on some
Linux distros install it separately with `sudo apt install python3-tk`),
and the packages in requirements.txt (`pip install -r requirements.txt`).

All cryptography, storage, and message logic lives in engine.py; this
file only builds the UI and calls into that module.
"""

import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime

import engine

try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


APP_TITLE = "Secure University Messenger"
EMOJIS = ["\U0001F600", "\U0001F44D", "\U0001F914", "\U0001F4DA",
          "\U0001F389", "\U0001F60A", "\U0001F622", "\U0001F525"]

LIGHT = {
    "bg": "#F4F6F8", "panel": "#FFFFFF", "fg": "#1B1E23", "muted": "#6B7280",
    "accent": "#2E74B5", "accent_fg": "#FFFFFF", "entry_bg": "#FFFFFF",
    "border": "#D8DEE4", "bubble_mine": "#DCEBFB", "bubble_theirs": "#EDEFF2",
    "error": "#C0392B", "ok": "#1E8449",
}
DARK = {
    "bg": "#14161A", "panel": "#1E2127", "fg": "#E6E9EF", "muted": "#9AA3AF",
    "accent": "#4C93D6", "accent_fg": "#0B0E12", "entry_bg": "#262A31",
    "border": "#31353D", "bubble_mine": "#274158", "bubble_theirs": "#2A2E36",
    "error": "#E57373", "ok": "#81C784",
}


class MessengerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("980x640")
        self.minsize(820, 540)

        engine.init_db()

        self.dark_mode = False
        self.theme = LIGHT
        self.session = None          # engine.Session once logged in
        self.current_partner = None

        self.container = tk.Frame(self)
        self.container.pack(fill="both", expand=True)

        self.show_login_screen()

    # -----------------------------------------------------------
    # Screen management
    # -----------------------------------------------------------
    def _clear_container(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        self.theme = DARK if self.dark_mode else LIGHT
        if self.session is None:
            self.show_login_screen()
        else:
            self.show_main_screen()

    # -----------------------------------------------------------
    # LOGIN / REGISTER SCREEN
    # -----------------------------------------------------------
    def show_login_screen(self):
        self._clear_container()
        t = self.theme
        self.configure(bg=t["bg"])

        outer = tk.Frame(self.container, bg=t["bg"])
        outer.pack(fill="both", expand=True)

        card = tk.Frame(outer, bg=t["panel"], highlightbackground=t["border"],
                         highlightthickness=1)
        card.place(relx=0.5, rely=0.5, anchor="center", width=420, height=460)

        tk.Label(card, text="\U0001F393  Secure University Messenger",
                 bg=t["panel"], fg=t["fg"], font=("Segoe UI", 15, "bold")
                 ).pack(pady=(28, 4))
        tk.Label(card, text="ElGamal-encrypted, digitally signed messaging",
                 bg=t["panel"], fg=t["muted"], font=("Segoe UI", 9)
                 ).pack(pady=(0, 20))

        form = tk.Frame(card, bg=t["panel"])
        form.pack(fill="x", padx=36)

        tk.Label(form, text="Username", bg=t["panel"], fg=t["fg"],
                 anchor="w", font=("Segoe UI", 9)).pack(fill="x")
        username_entry = tk.Entry(form, bg=t["entry_bg"], fg=t["fg"],
                                   relief="flat", highlightbackground=t["border"],
                                   highlightthickness=1)
        username_entry.pack(fill="x", ipady=6, pady=(2, 12))

        tk.Label(form, text="Password", bg=t["panel"], fg=t["fg"],
                 anchor="w", font=("Segoe UI", 9)).pack(fill="x")
        password_entry = tk.Entry(form, show="*", bg=t["entry_bg"], fg=t["fg"],
                                   relief="flat", highlightbackground=t["border"],
                                   highlightthickness=1)
        password_entry.pack(fill="x", ipady=6, pady=(2, 12))

        tk.Label(form, text="Role (used only when registering)", bg=t["panel"],
                 fg=t["fg"], anchor="w", font=("Segoe UI", 9)).pack(fill="x")
        role_var = tk.StringVar(value="student")
        role_combo = ttk.Combobox(form, textvariable=role_var,
                                   values=["student", "lecturer"], state="readonly")
        role_combo.pack(fill="x", pady=(2, 16))

        error_label = tk.Label(form, text="", bg=t["panel"], fg=t["error"],
                                font=("Segoe UI", 9), wraplength=340, justify="left")
        error_label.pack(fill="x")

        def do_login():
            username = username_entry.get().strip()
            password = password_entry.get()
            if not username or not password:
                error_label.config(text="Enter both username and password.")
                return
            try:
                self.session = engine.login(username, password)
            except engine.AuthError as e:
                error_label.config(text=str(e))
                return
            self.current_partner = None
            self.show_main_screen()

        def do_register():
            username = username_entry.get().strip()
            password = password_entry.get()
            role = role_var.get()
            if not username or not password:
                error_label.config(text="Enter both username and password.")
                return
            if len(password) < 6:
                error_label.config(text="Password should be at least 6 characters.")
                return
            try:
                engine.register_user(username, password, role)
            except ValueError as e:
                error_label.config(text=str(e))
                return
            error_label.config(fg=t["ok"], text=f"Account created for '{username}'. "
                                                 f"You can log in now.")

        btn_row = tk.Frame(form, bg=t["panel"])
        btn_row.pack(fill="x", pady=(4, 24))

        login_btn = tk.Button(btn_row, text="Log In", command=do_login,
                               bg=t["accent"], fg=t["accent_fg"], relief="flat",
                               font=("Segoe UI", 10, "bold"), activebackground=t["accent"])
        login_btn.pack(side="left", expand=True, fill="x", ipady=6, padx=(0, 6))

        register_btn = tk.Button(btn_row, text="Register", command=do_register,
                                  bg=t["panel"], fg=t["accent"], relief="flat",
                                  highlightbackground=t["accent"], highlightthickness=1,
                                  font=("Segoe UI", 10, "bold"))
        register_btn.pack(side="left", expand=True, fill="x", ipady=6, padx=(6, 0))

        theme_btn = tk.Button(card, text=("\u2600 Light Mode" if self.dark_mode else "\U0001F319 Dark Mode"),
                               command=self.toggle_dark_mode, bg=t["panel"], fg=t["muted"],
                               relief="flat", font=("Segoe UI", 8))
        theme_btn.place(relx=1.0, rely=1.0, anchor="se", x=-10, y=-8)

        password_entry.bind("<Return>", lambda ev: do_login())

    # -----------------------------------------------------------
    # MAIN SCREEN (after login)
    # -----------------------------------------------------------
    def show_main_screen(self):
        self._clear_container()
        t = self.theme
        self.configure(bg=t["bg"])
        session = self.session

        # ---- Top bar ----
        topbar = tk.Frame(self.container, bg=t["panel"], height=54,
                           highlightbackground=t["border"], highlightthickness=1)
        topbar.pack(fill="x", side="top")
        topbar.pack_propagate(False)

        tk.Label(topbar, text=f"\U0001F464 {session.username}  ({session.role})",
                 bg=t["panel"], fg=t["fg"], font=("Segoe UI", 11, "bold")
                 ).pack(side="left", padx=16)

        def make_top_button(text, cmd):
            return tk.Button(topbar, text=text, command=cmd, bg=t["panel"], fg=t["accent"],
                              relief="flat", font=("Segoe UI", 9, "bold"))

        make_top_button("Logout", self.do_logout).pack(side="right", padx=10)
        make_top_button(("\u2600 Light" if self.dark_mode else "\U0001F319 Dark"),
                         self.toggle_dark_mode).pack(side="right", padx=10)
        make_top_button("\U0001F50D Search", self.open_search_dialog).pack(side="right", padx=10)
        make_top_button("\U0001F4F1 My QR Code", self.open_qr_dialog).pack(side="right", padx=10)

        # ---- Body: contacts | chat ----
        body = tk.Frame(self.container, bg=t["bg"])
        body.pack(fill="both", expand=True)

        # Contacts panel
        contacts_frame = tk.Frame(body, bg=t["panel"], width=230,
                                   highlightbackground=t["border"], highlightthickness=1)
        contacts_frame.pack(side="left", fill="y")
        contacts_frame.pack_propagate(False)

        tk.Label(contacts_frame, text="CONTACTS", bg=t["panel"], fg=t["muted"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=14, pady=(14, 4))

        self.contacts_listbox = tk.Listbox(
            contacts_frame, bg=t["panel"], fg=t["fg"], relief="flat",
            selectbackground=t["accent"], selectforeground=t["accent_fg"],
            highlightthickness=0, font=("Segoe UI", 10), activestyle="none",
        )
        self.contacts_listbox.pack(fill="both", expand=True, padx=8, pady=4)
        self.contacts_listbox.bind("<<ListboxSelect>>", self.on_select_contact)

        self.all_users = engine.list_users(exclude=session.username)
        for u in self.all_users:
            self.contacts_listbox.insert("end", f"{u['username']}  ({u['role']})")

        # Chat panel
        chat_frame = tk.Frame(body, bg=t["bg"])
        chat_frame.pack(side="left", fill="both", expand=True)

        self.chat_header = tk.Label(chat_frame, text="Select a contact to start chatting",
                                     bg=t["bg"], fg=t["muted"], font=("Segoe UI", 10, "italic"),
                                     anchor="w")
        self.chat_header.pack(fill="x", padx=16, pady=(12, 4))

        text_area_frame = tk.Frame(chat_frame, bg=t["bg"])
        text_area_frame.pack(fill="both", expand=True, padx=16)

        self.chat_text = tk.Text(text_area_frame, bg=t["panel"], fg=t["fg"], relief="flat",
                                  wrap="word", state="disabled", font=("Segoe UI", 10),
                                  padx=10, pady=10)
        scrollbar = tk.Scrollbar(text_area_frame, command=self.chat_text.yview)
        self.chat_text.configure(yscrollcommand=scrollbar.set)
        self.chat_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.chat_text.tag_configure("mine", justify="right", background=t["bubble_mine"],
                                      lmargin1=80, lmargin2=80, rmargin=6, spacing3=10)
        self.chat_text.tag_configure("theirs", justify="left", background=t["bubble_theirs"],
                                      lmargin1=6, rmargin=80, spacing3=10)
        self.chat_text.tag_configure("meta", font=("Segoe UI", 7), foreground=t["muted"])
        self.chat_text.tag_configure("warn", font=("Segoe UI", 7, "bold"), foreground=t["error"])

        # Emoji row
        emoji_row = tk.Frame(chat_frame, bg=t["bg"])
        emoji_row.pack(fill="x", padx=16, pady=(6, 0))
        for em in EMOJIS:
            tk.Button(emoji_row, text=em, command=lambda e=em: self.insert_emoji(e),
                      bg=t["bg"], relief="flat", font=("Segoe UI Emoji", 12)
                      ).pack(side="left")

        # Input row
        input_row = tk.Frame(chat_frame, bg=t["bg"])
        input_row.pack(fill="x", padx=16, pady=10)

        self.message_entry = tk.Entry(input_row, bg=t["entry_bg"], fg=t["fg"], relief="flat",
                                       highlightbackground=t["border"], highlightthickness=1,
                                       font=("Segoe UI", 10))
        self.message_entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        self.message_entry.bind("<Return>", lambda ev: self.send_current_message())

        tk.Button(input_row, text="Send", command=self.send_current_message,
                  bg=t["accent"], fg=t["accent_fg"], relief="flat",
                  font=("Segoe UI", 10, "bold")).pack(side="left", ipady=4, ipadx=10)

        # Export row
        export_row = tk.Frame(chat_frame, bg=t["bg"])
        export_row.pack(fill="x", padx=16, pady=(0, 14))
        tk.Button(export_row, text="Export as TXT", command=lambda: self.export_conversation("txt"),
                  bg=t["panel"], fg=t["accent"], relief="flat", font=("Segoe UI", 8)
                  ).pack(side="left", padx=(0, 8))
        tk.Button(export_row, text="Export as PDF", command=lambda: self.export_conversation("pdf"),
                  bg=t["panel"], fg=t["accent"], relief="flat", font=("Segoe UI", 8)
                  ).pack(side="left")

        # Restore previously selected contact, if any
        if self.current_partner:
            self.load_conversation(self.current_partner)

    # -----------------------------------------------------------
    # Actions
    # -----------------------------------------------------------
    def do_logout(self):
        self.session = None
        self.current_partner = None
        self.show_login_screen()

    def insert_emoji(self, emoji_char):
        self.message_entry.insert("insert", emoji_char)
        self.message_entry.focus_set()

    def on_select_contact(self, _event):
        sel = self.contacts_listbox.curselection()
        if not sel:
            return
        username = self.all_users[sel[0]]["username"]
        self.load_conversation(username)

    def load_conversation(self, partner_username):
        self.current_partner = partner_username
        t = self.theme
        self.chat_header.config(text=f"Conversation with {partner_username}", fg=t["fg"])

        self.chat_text.config(state="normal")
        self.chat_text.delete("1.0", "end")

        try:
            messages = engine.get_conversation(self.session, partner_username)
        except Exception as e:
            messagebox.showerror("Error", f"Could not load conversation:\n{e}")
            self.chat_text.config(state="disabled")
            return

        for m in messages:
            when = datetime.fromtimestamp(m["timestamp"]).strftime("%d %b %H:%M")
            tag = "mine" if m["sender"] == self.session.username else "theirs"
            status = "\u2713 verified" if m["verified"] else "\u26A0 signature NOT verified"
            status_tag = "meta" if m["verified"] else "warn"

            self.chat_text.insert("end", f"{m['sender']} \u00b7 {when} \u00b7 {status}\n",
                                   (status_tag,))
            self.chat_text.insert("end", m["text"] + "\n\n", (tag,))

        self.chat_text.config(state="disabled")
        self.chat_text.see("end")

    def send_current_message(self):
        if not self.current_partner:
            messagebox.showinfo("Select a contact", "Choose a contact from the list first.")
            return
        text = self.message_entry.get().strip()
        if not text:
            return
        try:
            engine.send_message(self.session, self.current_partner, text)
            engine.backup_database()
        except Exception as e:
            messagebox.showerror("Could not send message", str(e))
            return
        self.message_entry.delete(0, "end")
        self.load_conversation(self.current_partner)

    def export_conversation(self, fmt):
        if not self.current_partner:
            messagebox.showinfo("Select a contact", "Choose a contact from the list first.")
            return
        default_name = f"chat_{self.session.username}_{self.current_partner}.{fmt}"
        filetypes = [("Text file", "*.txt")] if fmt == "txt" else [("PDF file", "*.pdf")]
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}", initialfile=default_name, filetypes=filetypes,
        )
        if not path:
            return
        try:
            if fmt == "txt":
                engine.export_conversation_txt(self.session, self.current_partner, path)
            else:
                engine.export_conversation_pdf(self.session, self.current_partner, path)
        except Exception as e:
            messagebox.showerror("Export failed", str(e))
            return
        messagebox.showinfo("Export complete", f"Conversation exported to:\n{path}")

    # -----------------------------------------------------------
    # Search dialog
    # -----------------------------------------------------------
    def open_search_dialog(self):
        t = self.theme
        win = tk.Toplevel(self)
        win.title("Search Messages")
        win.geometry("460x420")
        win.configure(bg=t["panel"])

        tk.Label(win, text="Search your messages", bg=t["panel"], fg=t["fg"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=16, pady=(16, 4))

        entry = tk.Entry(win, bg=t["entry_bg"], fg=t["fg"], relief="flat",
                          highlightbackground=t["border"], highlightthickness=1)
        entry.pack(fill="x", padx=16, ipady=6)

        results_box = tk.Listbox(win, bg=t["panel"], fg=t["fg"], relief="flat",
                                  highlightthickness=0, font=("Segoe UI", 9))
        results_box.pack(fill="both", expand=True, padx=16, pady=12)
        matches_holder = {"matches": []}

        def do_search(_event=None):
            keyword = entry.get().strip()
            results_box.delete(0, "end")
            if not keyword:
                return
            matches = engine.search_messages(self.session, keyword)
            matches_holder["matches"] = matches
            if not matches:
                results_box.insert("end", "No matches found.")
                return
            for m in matches:
                when = datetime.fromtimestamp(m["timestamp"]).strftime("%d %b %H:%M")
                snippet = m["text"] if len(m["text"]) <= 60 else m["text"][:57] + "..."
                results_box.insert("end", f"[{m['partner']} \u00b7 {when}] {m['sender']}: {snippet}")

        def open_selected(_event=None):
            sel = results_box.curselection()
            if not sel or not matches_holder["matches"]:
                return
            match = matches_holder["matches"][sel[0]]
            self.load_conversation(match["partner"])
            win.destroy()

        entry.bind("<Return>", do_search)
        results_box.bind("<Double-Button-1>", open_selected)

        tk.Button(win, text="Search", command=do_search, bg=t["accent"], fg=t["accent_fg"],
                  relief="flat", font=("Segoe UI", 9, "bold")).pack(pady=(0, 14), ipadx=10, ipady=4)

    # -----------------------------------------------------------
    # QR code dialog (share my ElGamal public key)
    # -----------------------------------------------------------
    def open_qr_dialog(self):
        t = self.theme
        win = tk.Toplevel(self)
        win.title("My Public Key QR Code")
        win.configure(bg=t["panel"])

        tk.Label(win, text=f"Public key for {self.session.username}", bg=t["panel"],
                 fg=t["fg"], font=("Segoe UI", 11, "bold")).pack(padx=20, pady=(16, 8))

        payload = engine.public_key_qr_payload(self.session.username)
        qr_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                f"qr_{self.session.username}.png")
        try:
            engine.make_qr_image(payload, qr_path)
        except Exception as e:
            tk.Label(win, text=f"Could not generate QR code:\n{e}", bg=t["panel"],
                      fg=t["error"]).pack(padx=20, pady=20)
            return

        if PIL_AVAILABLE:
            img = Image.open(qr_path).resize((260, 260))
            photo = ImageTk.PhotoImage(img)
        else:
            photo = tk.PhotoImage(file=qr_path)

        label = tk.Label(win, image=photo, bg=t["panel"])
        label.image = photo  # keep a reference so it isn't garbage-collected
        label.pack(padx=20, pady=8)

        tk.Label(win, text="Other students/lecturers can scan this to import\n"
                            "your ElGamal public key for secure messaging.",
                 bg=t["panel"], fg=t["muted"], font=("Segoe UI", 8), justify="center"
                 ).pack(padx=20, pady=(0, 16))


def main():
    app = MessengerApp()
    app.mainloop()


if __name__ == "__main__":
    main()