import socket
import tkinter as tk
import subprocess
import tkinter.font as tkfont
import dns.resolver
import random
import subprocess
import threading

from datetime import datetime
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
from tkinter import scrolledtext


colorama_init()


# ====================================================
# network functions
# ====================================================


def get_ip_config():
    try:
        # Run ipconfig and capture output
        output = subprocess.check_output("ipconfig", shell=True, text=True)
        return output + "\n"
    except subprocess.CalledProcessError as e:
        return f"Error fetching ipconfig: {e}"


def get_ports(ip):
    open_port_list = []  # new empty list for storing ports
    for port in range(65535):  # check for all available ports
        try:
            serv = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM
            )  # create a new socket
            serv.bind((ip, port))  # bind socket with address
        except:
            open_port_list.append(port)
        serv.close()  # close connection

    return (
        f"Total listening ports:",
        len(open_port_list),
        f"The first 10 listening ports are:",
        open_port_list[:10],
    )


def get_ip():
    ip = socket.gethostbyname(socket.gethostname())  # getting ip-address of host
    return ip


def get_text_width():
    text_area.update_idletasks()  # Make sure layout is updated

    width = text_area.winfo_width()  # get textbox width in pixels
    font_name = text_area["font"]
    font = tkfont.Font(font=font_name)
    char_width = font.measure("=")

    if char_width == 0:  # safety check
        char_width = 7  # default fallback value

    num = (
        width // char_width
    )  # calculate number of characters for the text box width by dividing width by char width

    # Subtract a few characters to prevent overflow / wrapping

    separator = "=" * num
    return separator


def get_sys_details():
    border = get_text_width()
    hostname = socket.gethostname()  # get device name
    ip = get_ip()  # getting ip-address of host
    return (
        f"{border}\n"
        f"\nYour Computer's name registers as: {hostname}\n"
        f"Your IP address is currently {ip}\n"
        f"{border}\n"
    )


def get_dns_response():

    try:
        domain = get_dns_address()
        answer = dns.resolver.resolve(
            domain, "A"
        )  # query dns resolver for A (IPV4) for the address google.com
        response = []
        for rdata in answer:
            # print(rdata.to_text())
            response.append(rdata.to_text())
            # print(response)
            return domain, response, "success"

            # return result object containing a list of addresses
    except dns.resolver.NXDOMAIN:
        # print("Domain not found")
        return domain, [], "failure_nxdomain"
    except dns.resolver.Timeout:
        # print("DNS lookup timed out")
        return domain, [], "failure_timeout"


def get_dns_address():
    domain_name_list = [  # list of domains to translate
        "iana.org",
        "example.com",
        "google.com",
        "cloudflare.com",
    ]
    dns_choice = random.choice(domain_name_list)  # domain chosen randomly from the list
    # print(dns_choice)

    # add error handling?
    # add expected return ip handling?
    return dns_choice


def get_ping():
    try:
        out = subprocess.run(["ping", "google.com"], capture_output=True, timeout=10)
        output = out.stdout
        return output
    except subprocess.TimeoutExpired:
        return "Ping command timed out. Please check your internet connection."
    except Exception as e:
        return f"Ping error: {e}"

    # add other ping locations?


# ================================================================================
# create function to recreate output and display content
# ================================================================================


current_view = "home"


# reset view to home
def display_set_home():

    global current_view
    current_view = "home"
    display_refresh_output()


light_redrawn_views = [
    "display_dns_response",
    "display_ping",
    "display_ports",
]  # views with heavy processes that require redrawing only border content on resize


def display_refresh_output():

    border = get_text_width()

    if (
        current_view in light_redrawn_views
    ):  # for expensive GUI draws (dynamic processes not to be redone unless required)
        text_area.configure(state="normal")

        # Get current text excluding first line (old border)
        content = text_area.get("2.0", tk.END)

        # Delete first line (old border)
        text_area.delete("1.0", "2.0")

        # Insert new border line at the top
        text_area.insert("1.0", f"{border}\n")

        text_area.configure(state="disabled")
        # update timestamps
        current_time = datetime.now().strftime("%H:%M:%S")
        last_refreshed_label.config(text=f"Last Refreshed: {current_time}")
        return

    if current_view == "display_ip_config":  # all other views (static text displays)
        display_ip_config()
    elif current_view == "display_system_details":
        display_system_details()
    elif current_view == "display_port_info":
        display_port_info()
    elif current_view == "display_ip_config_info":
        display_ip_config_info()
    elif current_view == "display_about":
        display_about()

    else:  # fallback to return home
        text_area.configure(state="normal")  # Enable editing
        text_area.delete(1.0, tk.END)  # Clear existing content
        text_area.insert(tk.INSERT, f"{border}\n\n")
        text_area.insert(tk.INSERT, "Welcome to the MD Diagnostics Tool!\n")
        text_area.insert(tk.INSERT, f"\n{border}\n")

        text_area.configure(state="disabled")  # Make it read-only again

    current_time = datetime.now().strftime("%H:%M:%S")
    last_refreshed_label.config(text=f"Last Refreshed: {current_time}")


def display_ip_config():
    global current_view
    border = get_text_width()
    current_view = "display_ip_config"

    text_area.configure(state="normal")  # Enable editing
    text_area.delete(1.0, tk.END)  # Clear existing content
    text_area.insert(tk.INSERT, f"{border}\n")
    text_area.insert(tk.INSERT, get_ip_config())
    text_area.configure(state="disabled")  # Make it read-only again


def display_system_details():
    global current_view
    current_view = "display_system_details"
    border = get_text_width()

    text_area.configure(state="normal")  # Enable editing
    text_area.delete(1.0, tk.END)  # Clear existing content
    text_area.insert(tk.INSERT, f"{border}\n\n")
    text_area.insert(tk.INSERT, "System Details\n")
    text_area.insert(tk.INSERT, "\n")
    text_area.insert(tk.INSERT, get_sys_details())
    text_area.configure(state="disabled")  # Make it read-only again


def display_ports():
    global current_view
    border = get_text_width()
    current_view = "display_ports"

    text_area.configure(state="normal")  # Enable editing
    text_area.delete(1.0, tk.END)  # Clear existing content
    text_area.insert(tk.INSERT, "Scanning ports, please wait...\n")
    text_area.update()  # Force update to show message before blocking scan
    text_area.delete(1.0, tk.END)  # Clear existing content
    text_area.insert(tk.INSERT, f"{border}\n\n")
    result = get_ports(get_ip())
    for line in result:

        text_area.insert(tk.INSERT, str(line) + "\n")
    text_area.configure(state="disabled")  # Make it read-only again


def display_port_info():
    global current_view
    current_view = "display_port_info"
    border = get_text_width()

    text_area.configure(state="normal")  # Enable editing
    text_area.delete(1.0, tk.END)  # Clear existing content
    text_area.insert(tk.INSERT, f"{border}\n\n")
    text_area.insert(tk.INSERT, "Port Information\n")
    text_area.insert(tk.INSERT, f"\n{border}\n")
    text_area.configure(state="disabled")  # Make it read-only again


def display_ip_config_info():
    global current_view
    current_view = "display_ip_config_info"
    border = get_text_width()

    text_area.configure(state="normal")  # Enable editing
    text_area.delete(1.0, tk.END)  # Clear existing content
    text_area.insert(tk.INSERT, f"{border}\n\n")
    text_area.insert(tk.INSERT, "IP Config Explained\n")
    text_area.insert(tk.INSERT, f"\n{border}\n")
    text_area.configure(state="disabled")  # Make it read-only again


def display_ping():
    global current_view
    current_view = "display_ping"
    border = get_text_width()

    text_area.configure(state="normal")  # Enable editing
    text_area.delete(1.0, tk.END)  # Clear existing content
    text_area.insert(tk.INSERT, f"{border}\n\n")
    text_area.insert(tk.INSERT, "Ping Status:\n")
    text_area.insert(tk.INSERT, f"\n{border}\n")
    text_area.insert(tk.INSERT, "\n Pinging 'google.com'...\n")
    text_area.configure(state="disabled")  # Make it read-only again
    text_area.update()

    def run_ping():
        result = get_ping()
        text_area.configure(state="normal")  # Enable editing
        text_area.insert(tk.INSERT, result)
        text_area.configure(state="disabled")  # Make it read-only again

    threading.Thread(target=run_ping).start()
    text_area.configure(state="disabled")  # Make it read-only again


def display_dns_response():

    global current_view
    current_view = "display_dns_response"
    border = get_text_width()

    domain, dnsresponse, status = get_dns_response()
    text_area.configure(state="normal")  # Enable editing
    text_area.delete(1.0, tk.END)  # Clear existing content
    text_area.insert(tk.INSERT, f"{border}\n\n")
    text_area.insert(tk.INSERT, "DNS Resolver\n")
    text_area.insert(tk.INSERT, f"\n{border}\n")
    text_area.insert(
        tk.INSERT,
        "DNS Domain resolvers used a from a list of popular DNS test addresses.",
    )
    text_area.insert(tk.INSERT, "\n")
    if status == "success":
        text_area.insert(
            tk.INSERT,
            f"For the address '{domain}', the DNS response was ({','.join(dnsresponse)}).",
        )
    elif status == "failure_nxdomain":
        text_area.insert(
            tk.INSERT,
            f"For the address '{domain}', there was no response. This domain does not exist.)",
        )
    elif status == "failure_timeout":
        text_area.insert(
            tk.INSERT,
            f"For the address '{domain}', the DNS query timed out. Please check your internet connection.)",
        )
    text_area.configure(state="disabled")  # Make it read-only again


def display_about():
    global current_view
    current_view = "display_about"
    border = get_text_width()

    text_area.configure(state="normal")  # Enable editing
    text_area.delete(1.0, tk.END)  # Clear existing content
    text_area.insert(tk.INSERT, f"{border}\n\n")
    text_area.insert(tk.INSERT, "About the MD Diagnostics Tool\n")
    text_area.insert(tk.INSERT, f"\n{border}\n")
    text_area.configure(state="disabled")  # Make it read-only again


# ====================================================
# GUI Setup
# ====================================================

# initialize root tk window properties
root = tk.Tk()
root.iconbitmap(default="netico.ico")
root.title("MD System Diagnostics Tool")
root.geometry("900x600")
# add taskbar icon?


def on_resize(
    event,
):  # function to refresh output on resize (unless light redraw, with partial refresh)
    if current_view in light_redrawn_views or current_view == "home":
        display_refresh_output()


root.bind("<Configure>", on_resize)


# =====================================================
# create sidebar frame
# =====================================================


sidebar_frame = tk.Frame(root, width=300, bg="#f0f0f0")
sidebar_frame.pack(side="left", fill="y")


# =====================================================
# Subframe in Sidebar for buttons for IP Config
# =====================================================


ip_config_frame = tk.Frame(sidebar_frame, bg="#f0f0f0")
ip_config_frame.pack(side="top", fill="x", padx=10, pady=0)


# =====================================================
# Subframe in Sidebar for buttons for Ports
# =====================================================


port_frame = tk.Frame(sidebar_frame, bg="#f0f0f0")
port_frame.pack(side="top", fill="x", padx=10, pady=0)


# =====================================================
# create footer frame
# =====================================================


footer_frame = tk.Frame(root, height=200, bg="#f0f0f0")
footer_frame.pack(side="bottom", fill="x")

right_button_frame = tk.Frame(footer_frame, bg="#f0f0f0")
right_button_frame.pack(side="right", padx=20, pady=10)


# =====================================================
# create text frame
# =====================================================


main_frame = tk.Frame(root)
main_frame.pack(side="right", fill="both", expand=True)

text_area = scrolledtext.ScrolledText(main_frame, wrap=tk.NONE, font=("Segoe UI", 10))
text_area.pack(expand=True, fill="both", padx=10, pady=10)


# =====================================================
# Buttons/Label Elements for Sidebar Frame
# =====================================================


# add a refresh label


last_refreshed_label = tk.Label(
    sidebar_frame, text="Last Refreshed: N/A", font=("Segoe UI", 10), bg="#f0f0f0"
)
last_refreshed_label.pack(side="bottom", padx=20, pady=10)


# Add system details Button


system_details_button = tk.Button(
    sidebar_frame,
    text="System Details",
    command=display_system_details,
    font=("Segoe UI", 12),
)
system_details_button.pack(fill="x", padx=5, pady=2)


# Add ip config Button


ip_config_button = tk.Button(
    sidebar_frame, text="IP Config", command=display_ip_config, font=("Segoe UI", 12)
)
ip_config_button.pack(fill="x", padx=5, pady=3)


# add ipconfig info button


ipconfig_info_button = tk.Button(
    sidebar_frame,
    text="IP Config Info",
    command=display_ip_config_info,
    font=("Segoe UI", 12),
    bg="grey75",
)
ipconfig_info_button.pack(fill="x", padx=5, pady=3)


# Add port scans Button


port_scans_button = tk.Button(
    sidebar_frame, text="Ports", command=display_ports, font=("Segoe UI", 12)
)
port_scans_button.pack(fill="x", padx=5, pady=3)


# Add port info Button


port_info_button = tk.Button(
    sidebar_frame,
    text="Port Info",
    command=display_port_info,
    font=("Segoe UI", 12),
    bg="grey75",
)
port_info_button.pack(fill="x", padx=5, pady=3)


# add ping test button


ping_test_button = tk.Button(
    sidebar_frame, text="Ping Test", command=display_ping, font=("Segoe UI", 12)
)
ping_test_button.pack(fill="x", padx=5, pady=3)


# add packet dump test button


packet_analysis_button = tk.Button(
    sidebar_frame,
    text="TCP Packet Analysis",
    command=display_port_info,
    font=("Segoe UI", 12),
)
packet_analysis_button.pack(fill="x", padx=5, pady=3)


# add dns resolver button


dns_resolver_button = tk.Button(
    sidebar_frame,
    text="DNS Resolver",
    command=display_dns_response,
    font=("Segoe UI", 12),
)
dns_resolver_button.pack(fill="x", padx=5, pady=3)


# ====================================================
# Buttons for Footer Frame
# ====================================================


# add a close button


close_button = tk.Button(
    right_button_frame, text="Exit", command=root.quit, font=("Segoe UI", 12)
)
close_button.pack(side="right", padx=10, pady=10)


# add a home button


home_button = tk.Button(
    right_button_frame, text="Home", command=display_set_home, font=("Segoe UI", 12)
)
home_button.pack(side="right", padx=10, pady=10)


# add an about button


about_button = tk.Button(
    right_button_frame,
    text="About",
    command=display_about,
    font=("Segoe UI", 12),
)
about_button.pack(side="left", padx=10)


# Add Refresh Button


refresh_button = tk.Button(
    right_button_frame,
    text="Refresh",
    command=display_refresh_output,
    font=("Segoe UI", 12),
)
refresh_button.pack(side="left", padx=10)


# ====================================================
# Initial content load
# ====================================================

display_refresh_output()
# Start the GUI loop
root.mainloop()
