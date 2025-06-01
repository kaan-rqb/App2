import tkinter as tk
from tkinter import messagebox
import requests
import json
import os

USERS_FILE = "users.json"

admins = {
    "EminVNC": "EminVNC1234",
    "KaanVNC": "KaanVNC1234",
    "Hazir": "Hazirlan",
    "Hazir": "Hazirlan",
}

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)

users = load_users()

def ip_api_sorgula(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}").json()
        if r["status"] == "success":
            return (
                f"IP: {r['query']}\n"
                f"Ülke: {r['country']}\n"
                f"Bölge: {r['regionName']}\n"
                f"Şehir: {r['city']}\n"
                f"ISP: {r['isp']}\n"
                f"Zaman Dilimi: {r['timezone']}\n"
                f"Koordinatlar: {r['lat']}, {r['lon']}"
            )
        else:
            return "Geçersiz IP veya bilgi bulunamadı."
    except Exception as e:
        return f"Hata: {e}"

def ipinfo_sorgula(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json").json()
        if 'bogon' in r:
            return "Geçersiz IP veya bilgi bulunamadı."
        return (
            f"IP: {ip}\n"
            f"Şehir: {r.get('city','Bilinmiyor')}\n"
            f"Ülke: {r.get('country','Bilinmiyor')}\n"
            f"Bölge: {r.get('region','Bilinmiyor')}\n"
            f"Lokasyon: {r.get('loc','Bilinmiyor')}\n"
            f"ISP: {r.get('org','Bilinmiyor')}"
        )
    except Exception as e:
        return f"Hata: {e}"

def login():
    global current_user_is_admin
    username = login_username_entry.get().strip()
    password = login_password_entry.get().strip()

    if username in admins and admins[username] == password:
        current_user_is_admin = True
        show_main_frame()
        update_ui_for_user()
        return

    if username in users and users[username] == password:
        current_user_is_admin = False
        show_main_frame()
        update_ui_for_user()
    else:
        messagebox.showerror("Hata", "Kullanıcı adı veya şifre yanlış!")

def register():
    username = reg_username_entry.get().strip()
    password = reg_password_entry.get().strip()
    if username == "" or password == "":
        messagebox.showwarning("Uyarı", "Kullanıcı adı ve şifre boş olamaz!")
        return
    if username in users or username in admins:
        messagebox.showerror("Hata", "Bu kullanıcı adı zaten kayıtlı veya admin olarak ayrılmış!")
        return
    users[username] = password
    save_users(users)
    messagebox.showinfo("Başarılı", "Kayıt başarılı! Giriş yapabilirsiniz.")
    show_login_frame()

def show_register_frame():
    login_frame.pack_forget()
    register_frame.pack()

def show_login_frame():
    register_frame.pack_forget()
    main_frame.pack_forget()
    login_frame.pack()

def show_main_frame():
    login_frame.pack_forget()
    register_frame.pack_forget()
    main_frame.pack()

def update_ui_for_user():
    if current_user_is_admin:
        for rb in advanced_radio_buttons:
            rb.config(state="normal")
    else:
        for rb in advanced_radio_buttons:
            rb.config(state="disabled")
        sorgu_tipi.set(1)

def sorgula():
    ip = ip_entry.get().strip()
    if ip == "":
        messagebox.showwarning("Uyarı", "Lütfen IP adresi girin!")
        return

    secim = sorgu_tipi.get()
    if secim == 1:
        sonuc = ip_api_sorgula(ip)
    elif secim == 2 and current_user_is_admin:
        sonuc = ipinfo_sorgula(ip)
    else:
        sonuc = "Geçersiz sorgu tipi seçildi veya erişiminiz yok."

    result_label.config(text=sonuc)

def kendi_ip_cek():
    try:
        response = requests.get("https://api.ipify.org?format=json").json()
        ip_entry.delete(0, tk.END)
        ip_entry.insert(0, response["ip"])
    except:
        messagebox.showerror("Hata", "Kendi IP alınamadı!")

root = tk.Tk()
root.title("Sywen IP Sorgulama")

current_user_is_admin = False

ascii_art = """
  ___                              
 / __|  _  _  __ __ __  ___   _ _  
 \\__ \\ | || | \\ V  V / / -_) | ' \\ 
 |___/  \\_, |  \\_/\\_/  \\___| |_||_|
        |__/                        
"""

# Login Frame
login_frame = tk.Frame(root)
tk.Label(login_frame, text="Kullanıcı Adı:").pack(pady=5)
login_username_entry = tk.Entry(login_frame)
login_username_entry.pack(pady=5)
tk.Label(login_frame, text="Şifre:").pack(pady=5)
login_password_entry = tk.Entry(login_frame, show="*")
login_password_entry.pack(pady=5)
tk.Button(login_frame, text="Giriş Yap", command=login).pack(pady=10)
tk.Button(login_frame, text="Kayıt Ol", command=show_register_frame).pack(pady=5)
login_frame.pack()

# Register Frame
register_frame = tk.Frame(root)
tk.Label(register_frame, text="Yeni Kullanıcı Adı:").pack(pady=5)
reg_username_entry = tk.Entry(register_frame)
reg_username_entry.pack(pady=5)
tk.Label(register_frame, text="Yeni Şifre:").pack(pady=5)
reg_password_entry = tk.Entry(register_frame, show="*")
reg_password_entry.pack(pady=5)
tk.Button(register_frame, text="Kayıt Ol", command=register).pack(pady=10)
tk.Button(register_frame, text="Geri Dön", command=show_login_frame).pack(pady=5)

# Main Frame
main_frame = tk.Frame(root)

# ASCII art başlık (renkli)
title_label = tk.Label(main_frame, text=ascii_art, font=("Courier", 16, "bold"), fg="lime", justify="left", bg="black")
title_label.pack(fill="x", pady=10)

tk.Label(main_frame, text="IP Adresi Girin:", font=("Arial", 12, "bold")).pack(pady=5)
ip_entry = tk.Entry(main_frame, width=30, font=("Arial", 12))
ip_entry.pack(pady=5)
tk.Button(main_frame, text="Kendi IP'mi Getir", command=kendi_ip_cek).pack(pady=5)

tk.Label(main_frame, text="Sorgulama Yöntemi Seçin:", font=("Arial", 12, "bold")).pack(pady=5)
sorgu_tipi = tk.IntVar(value=1)
advanced_radio_buttons = []
rb1 = tk.Radiobutton(main_frame, text="1 - ip-api.com", variable=sorgu_tipi, value=1, font=("Arial", 11))
rb1.pack()
advanced_radio_buttons.append(rb1)
rb2 = tk.Radiobutton(main_frame, text="2 - ipinfo.io (Admin Only)", variable=sorgu_tipi, value=2, font=("Arial", 11))
rb2.pack()
advanced_radio_buttons.append(rb2)

tk.Button(main_frame, text="Sorgula", command=sorgula, font=("Arial", 12, "bold"), bg="green", fg="white").pack(pady=10)

result_label = tk.Label(main_frame, text="", justify="left", fg="cyan", bg="black", font=("Courier", 11), anchor="w")
result_label.pack(fill="both", expand=True, padx=10, pady=10)

# Arka planı siyah yapalım, böylece neon gibi görünür
root.configure(bg="black")
login_frame.configure(bg="black")
register_frame.configure(bg="black")
main_frame.configure(bg="black")

# Giriş ve kayıt frame içindeki label ve entrylerin rengini ayarla
for frame in [login_frame, register_frame]:
    for widget in frame.winfo_children():
        if isinstance(widget, tk.Label):
            widget.config(bg="black", fg="white", font=("Arial", 11, "bold"))
        if isinstance(widget, tk.Entry):
            widget.config(bg="gray15", fg="white", insertbackground="white")
        if isinstance(widget, tk.Button):
            widget.config(bg="green", fg="white", font=("Arial", 11, "bold"))

root.mainloop()