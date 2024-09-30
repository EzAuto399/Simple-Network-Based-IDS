import threading
import time
from scapy.all import sniff
from collections import defaultdict
import tkinter as tk
from tkinter import scrolledtext, messagebox
import smtplib
from email.mime.text import MIMEText
import os

# Configuration for email alerts (optional)
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
EMAIL_ADDRESS = 'your_email@gmail.com'
EMAIL_PASSWORD = 'your_password'
ALERT_RECIPIENT = 'recipient_email@gmail.com'

# Threshold for detecting a potential port scan
THRESHOLD = 100
TIME_WINDOW = 60  # seconds

# Dictionary to store the number of connection attempts per IP
connection_attempts = defaultdict(int)
lock = threading.Lock()

class IDS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Network-Based IDS")
        self.is_running = False

        # Create Start and Stop buttons
        self.start_button = tk.Button(root, text="Start Monitoring", command=self.start_monitoring, bg='green', fg='white', width=20)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(root, text="Stop Monitoring", command=self.stop_monitoring, bg='red', fg='white', width=20, state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        # Create a scrolled text area for logs
        self.log_area = scrolledtext.ScrolledText(root, width=80, height=20, state='disabled')
        self.log_area.pack(pady=10)

        # Start a thread to reset counters periodically
        self.reset_thread = threading.Thread(target=self.reset_counters, daemon=True)
        self.reset_thread.start()

    def start_monitoring(self):
        if not self.is_running:
            self.is_running = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.log_message("Starting Network-Based IDS...")
            # Start sniffing in a separate thread
            self.sniff_thread = threading.Thread(target=self.start_sniffing, daemon=True)
            self.sniff_thread.start()

    def stop_monitoring(self):
        if self.is_running:
            self.is_running = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.log_message("Stopping Network-Based IDS...")
            # Scapy's sniff function does not provide a direct way to stop.
            # One workaround is to use a global variable to control the sniffing.
            # However, for simplicity, we'll let the thread finish.

    def start_sniffing(self):
        sniff(filter="tcp", prn=self.packet_callback, store=0, stop_filter=lambda x: not self.is_running)

    def packet_callback(self, packet):
        if not self.is_running:
            return True  # Stop sniffing

        if packet.haslayer('TCP'):
            src_ip = packet['IP'].src
            with lock:
                connection_attempts[src_ip] += 1
                count = connection_attempts[src_ip]
            self.log_message(f"Connection attempt from {src_ip}: {count}")

            if count == THRESHOLD:
                self.alert(src_ip, count)

    def alert(self, src_ip, count):
        alert_message = f"*** ALERT *** Potential port scan detected from {src_ip} with {count} attempts."
        self.log_message(alert_message)
        # Send email alert (optional)
        # Uncomment the following line if you have configured email settings
        # self.send_email_alert(src_ip, count)
        # Optionally, show a popup alert
        messagebox.showwarning("Security Alert", alert_message)

    def send_email_alert(self, src_ip, count):
        subject = f"ALERT: Potential Port Scan Detected from {src_ip}"
        body = f"Source IP {src_ip} has made {count} connection attempts in the last {TIME_WINDOW} seconds."
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = ALERT_RECIPIENT

        try:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, ALERT_RECIPIENT, msg.as_string())
            server.quit()
            self.log_message(f"Email alert sent to {ALERT_RECIPIENT} for IP {src_ip}")
        except Exception as e:
            self.log_message(f"Failed to send email alert: {e}")

    def reset_counters(self):
        while True:
            time.sleep(TIME_WINDOW)
            with lock:
                connection_attempts.clear()
            self.log_message("Connection attempt counters have been reset.")

    def log_message(self, message):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')


def main():
    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
