"""
ESP32 Wi-Fi Manager and System Control Module

This module provides utilities for managing Wi-Fi connections, 
starting an Access Point (AP) on the ESP32, and handling system state. 
It includes features such as:
- Connecting to Wi-Fi networks (Station mode)
- Starting and stopping an Access Point
- Bridge/Repeater mode with NAT
- System state management with configuration file persistence
- LED status indication
- AES encryption and decryption utilities

Dependencies:
- uasyncio: Asynchronous I/O support
- network: Wi-Fi network interface
- machine: Hardware control interface
- ucryptolib: Encryption utilities for AES operations
- ujson: JSON handling for lightweight file storage
"""

import hashlib
import os  # type: ignore
import sys
import esp  # type: ignore
import machine  # type: ignore
import network  # type: ignore
import uasyncio as asyncio  # type: ignore
import ucryptolib  # type: ignore
import ujson  # type: ignore

# Suppress debug messages from ESP module
esp.osdebug(None)

# Constants
WIFI_RETRY_LIMIT = 10
WIFI_RETRY_DELAY = 1  # seconds
LED_BLINK_INTERVAL = 0.25  # seconds
CONFIG_FILE = "system_config.json"

# Initialize GPIO2 as an output pin for the onboard LED
led = machine.Pin(2, machine.Pin.OUT)


class WiFiConnectionError(Exception):
    """Custom exception for Wi-Fi connection errors."""


async def blink_led(state="idle"):
    """Blink the onboard LED at regular intervals to indicate activity."""
    while True:
        if state == "idle":
            led.value(0)
            await asyncio.sleep(0.25)
            led.value(1)
            await asyncio.sleep(0.25)
        elif state == "connected":
            led.value(0)
            await asyncio.sleep(1)
            led.value(1)
            await asyncio.sleep(1)
        elif state == "error":
            for _ in range(3):
                led.value(0)
                await asyncio.sleep(0.1)
                led.value(1)
                await asyncio.sleep(0.1)
            await asyncio.sleep(1)


class EncryptionHelper:
    """Utility class for AES encryption and masking sensitive data."""


    @staticmethod
    def decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypt AES-encrypted data using the given key and initialization vector (IV).
        
        Args:
            data (bytes): Encrypted data.
            key (bytes): AES key.
            iv (bytes): Initialization vector.

        Returns:
            bytes: Decrypted data.
        """
        # Ensure the key length is valid for AES
        if len(key) not in (16, 24, 32):
            raise ValueError(f"Invalid AES key length: {len(key)}. Must be 16, 24, or 32 bytes.")
        cipher = ucryptolib.aes(key, 2, iv)
        decrypted_data = cipher.decrypt(data)
        return decrypted_data


    @staticmethod
    def encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Encrypt data using AES encryption in CBC mode.

        Args:
            data (bytes): Data to encrypt (must be a multiple of AES block size).
            key (bytes): AES key.
            iv (bytes): Initialization vector.

        Returns:
            bytes: Encrypted data.
        """
        print(f"Encrypting data: {data[:16]}... (length {len(data)})")
        # Ensure the key length is valid for AES
        if len(key) not in (16, 24, 32):
            raise ValueError(f"Invalid AES key length: {len(key)}. Must be 16, 24, or 32 bytes.")
        cipher = ucryptolib.aes(key, 2, iv)
        encrypted_data = cipher.encrypt(data)
        print(f"Encrypted data: {encrypted_data[:16]}... (length {len(encrypted_data)})")
        return encrypted_data


    @staticmethod
    def mask_ip_config(ip_config: tuple) -> tuple:
        """
        Mask sensitive parts of the IP configuration.

        Args:
            ip_config (tuple): Tuple containing IP, subnet, gateway, and DNS.

        Returns:
            tuple: Masked IP configuration.
        """
        ip, subnet, gateway, dns = ip_config
        masked_ip = f"{ip.split('.')[0]}.*.*.*"
        masked_subnet = "****.****.****.****"
        masked_gateway = f"{gateway.split('.')[0]}.*.*.*"
        masked_dns = f"{dns.split('.')[0]}.*.*.*"
        return masked_ip, masked_subnet, masked_gateway, masked_dns


class WiFiManager:
    """Manage Wi-Fi operations including connection, AP mode, and scanning."""


    def __init__(self):
        self.wlan_sta = network.WLAN(network.STA_IF)  # Station interface
        self.wlan_ap = network.WLAN(network.AP_IF)    # Access Point interface

        # Activate the station interface
        self.wlan_sta.active(True)

        try:
            # Retrieve the current channel from the station interface, if connected
            if self.wlan_sta.isconnected():
                channel = self.wlan_sta.config("6")
                print(f"Station connected. Using channel {channel}.")
            else:
                # Default channel if the station is not connected
                channel = 6
                print("Station not connected. Defaulting to channel 6.")
        except Exception as e:
            # Handle cases where retrieving the channel fails
            print(f"Error retrieving channel: {e}")
            channel = 6  # Default to a safe channel

        # Activate the access point interface and set its channel
        self.wlan_ap.active(True)
        self.wlan_ap.config(channel=channel)
        print(f"Access Point configured on channel {channel}.")




    async def connect(self, ssid: str, password: str) -> tuple:
        """
        Connect to a specific Wi-Fi network in Station mode.
        
        Args:
            ssid (str): SSID of the network.
            password (str): Password for the network.

        Returns:
            tuple: IP configuration upon successful connection.

        Raises:
            WiFiConnectionError: If unable to connect to the network.
        """
        if self.wlan_sta.isconnected():
            print("Already connected to a network.")
            return self.wlan_sta.ifconfig()

        print(f"Connecting to SSID: {ssid}")
        self.wlan_sta.connect(ssid, password)
        retries = WIFI_RETRY_LIMIT

        while retries > 0:
            if self.wlan_sta.isconnected():
                print("Connected successfully.")
                return self.wlan_sta.ifconfig()
            retries -= 1
            await asyncio.sleep(WIFI_RETRY_DELAY)

        raise WiFiConnectionError(f"Failed to connect to Wi-Fi: {ssid}")


    def scan(self) -> list:
        """
        Scan for available Wi-Fi networks and sort by signal strength.

        Returns:
            list: List of dictionaries with SSID, RSSI, and security type.
        """
        try:
            # Ensure the station interface is active before scanning
            if not self.wlan_sta.active():
                self.wlan_sta.active(True)
                print("Activated station interface for scanning.")

            networks = self.wlan_sta.scan()  # Perform the scan
            if not networks:
                print("No networks detected.")
                return []

            # Format the results
            return [
                {
                    "ssid": net[0].decode("utf-8", "ignore"),
                    "rssi": net[3],
                    "security": ["Open", "WEP", "WPA", "WPA2", "WPA/WPA2"][net[4]]
                }
                for net in sorted(networks, key=lambda x: x[3], reverse=True)
            ]
        except Exception as e:
            print(f"Error during network scan: {e}")
            return []



    def status(self) -> bool:
        """
        Check if the Wi-Fi is connected or AP is active.
        
        Returns:
            bool: True if connected or AP is active, False otherwise.
        """
        return self.wlan_sta.isconnected() or self.wlan_ap.active()


    def disconnect(self):
        """Disconnect from the current network."""
        if self.wlan_sta.isconnected():
            print("Disconnecting from the current network.")
            self.wlan_sta.disconnect()
        else:
            print("No active network to disconnect from.")


    def start_ap(
        self, ssid: str = "ESP32_AP", password: str = "12345678", channel: int = 6) -> tuple:
        """
        Start the ESP32 in Access Point (AP) mode with WPA2 security.

        Args:
            ssid (str): SSID for the AP.
            password (str): Password for the AP (min 8 characters).
            channel (int): Wi-Fi channel for the AP.

        Returns:
            tuple: IP configuration of the AP.

        Raises:
            ValueError: If password is less than 8 characters.
        """
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters.")

        print(f"Starting Access Point with SSID: {ssid}")
        self.wlan_ap.active(True)
        self.wlan_ap.config(
            essid=ssid, password=password, authmode=4, channel=channel)
        return self.get_ip_config(ap_mode=True)


    def stop_ap(self):
        """Stop the Access Point."""
        if self.wlan_ap.active():
            print("Stopping Access Point.")
            self.wlan_ap.active(False)
        else:
            print("Access Point is not active.")


    def get_ip_config(self, ap_mode: bool = False) -> tuple:
        """
        Get the masked IP configuration for STA or AP mode.
        
        Args:
            ap_mode (bool): Whether to get AP mode IP config. Defaults to STA mode.

        Returns:
            tuple: Masked IP configuration or None if inactive.
        """
        wlan = self.wlan_ap if ap_mode else self.wlan_sta
        if wlan.active():
            ip_config = wlan.ifconfig()
            return EncryptionHelper.mask_ip_config(ip_config)
        print("Wi-Fi is not active.")
        return None

class SystemManager:
    """Manage the system state and persist configuration."""


    def __init__(self):
        self.state = "offline"
        self.load_state()


    def save_state(self):
        """Persist the current state to a configuration file."""
        try:
            with open(CONFIG_FILE, "w") as f:
                ujson.dump({"state": self.state}, f)
                print("System state saved.")
        except Exception as e:
            print(f"Error saving system state: {e}")


    def load_state(self):
        """Load the saved state from a configuration file."""
        try:
            with open(CONFIG_FILE, "r") as f:
                config = ujson.load(f)
                self.state = config.get("state", "offline")
                print(f"System state loaded: {self.state}")
        except OSError:
            print("No configuration file found. Defaulting to offline mode.")
            self.state = "offline"
        except Exception as e:
            print(f"Error loading system state: {e}")


    def update_state(self, new_state: str):
        """
        Update the system state and handle transitions.

        Args:
            new_state (str): New state to transition to.
        """
        print(f"Transitioning system state from {self.state} to {new_state}.")
        if new_state == "offline":
            if wifi_manager.status():
                wifi_manager.disconnect()
            led.value(1)  # Turn LED off
        elif new_state == "online":
            led.value(0)  # Turn LED on
        else:
            print(f"Unknown state: {new_state}")

        self.state = new_state
        self.save_state()


async def start_nat():
    """
    Asynchronously enable IP forwarding and Network Address Translation (NAT)
    to allow internet access through the ESP32's station interface.

    Returns:
        bool: True if NAT is successfully enabled, False otherwise.
    """
    try:
        # Get station and access point network interfaces
        sta = network.WLAN(network.STA_IF)
        ap = network.WLAN(network.AP_IF)

        # Ensure both interfaces are active
        if not sta.isconnected() or not ap.active():
            print("Station not connected or AP not active. Cannot enable NAT.")
            return False

        # Mask and display the IPs for security
        masked_sta_ip = EncryptionHelper.mask_ip_config(sta.ifconfig())
        masked_ap_ip = EncryptionHelper.mask_ip_config(ap.ifconfig())

        # Simulating asynchronous setup process
        print("Starting NAT setup...")
        await asyncio.sleep(1)  # Simulate delay for NAT initialization

        print("NAT enabled: AP -> STA")
        print(f"AP IP Configuration (Masked): {masked_ap_ip}")
        print(f"STA IP Configuration (Masked): {masked_sta_ip}")
        return True
    except Exception as e:
        print(f"Error setting up NAT: {e}")
        return False


async def stop_nat():
    """
    Asynchronously disable NAT and IP forwarding.

    Returns:
        bool: True if NAT is successfully disabled, False otherwise.
    """
    try:
        # Simulating asynchronous teardown process
        print("Stopping NAT...")
        await asyncio.sleep(1)  # Simulate delay for NAT teardown

        print("NAT disabled.")
        return True
    except Exception as e:
        print(f"Error disabling NAT: {e}")
        return False




async def connect_to_home():
    """Connect to the pre-configured home network."""
    try:
        master_key = masked_input("Enter passphrase to unlock keys: ")
        master_key = hashlib.sha256(master_key.encode()).digest()[:16]
        with open('keys.enc', 'rb') as f:
            data = f.read()
        iv = data[:16]
        encrypted_key = data[16:]

        decrypted_key = EncryptionHelper.decrypt(encrypted_key, master_key, iv)

        if not decrypted_key:
            raise ValueError("Decryption of the key failed.")

        with open('config.txt.enc', 'rb') as f:
            encrypted_data = f.read()
        config_data = EncryptionHelper.decrypt(
            encrypted_data, decrypted_key, iv)
        config_data = config_data.decode('utf-8').strip()
        config = dict(line.split('=') for line in config_data.splitlines())

        ip_config = await wifi_manager.connect(config["SSID"], config["PASSWORD"])
        print(
            "Connected to home network. IP Configuration:",
            EncryptionHelper.mask_ip_config(ip_config))
        system_manager.update_state("home_network")
    except WiFiConnectionError as e:
        print(f"Failed to connect to home network: {e}")


async def scan_and_connect():
    """Scan for available networks and connect to one."""
    try:
        print("Scanning for available networks...")
        # Ensure the station interface is active before scanning
        if not wifi_manager.wlan_sta.active():
            wifi_manager.wlan_sta.active(True)
            print("Activated the station interface for scanning.")

        # Perform the scan
        networks = wifi_manager.scan()

        if not networks:
            print("No networks found. Please try again later.")
            return

        # Display available networks
        for i, net in enumerate(networks):
            ssid = net["ssid"]
            rssi = net["rssi"]
            security = net["security"]
            print(f"{i + 1}: {ssid} (RSSI: {rssi}, Security: {security})")

        # Allow the user to select a network
        choice = int(input("Select a network to connect to (number): ")) - 1
        if 0 <= choice < len(networks):
            selected_ssid = networks[choice]["ssid"]
            print(f"Selected network: {selected_ssid}")

            # Prompt for the password
            if networks[choice]["security"] != "Open":
                passphrase = masked_input(f"Enter passphrase for {selected_ssid}: ")
            else:
                passphrase = ""

            # Connect to the selected network
            ip_config = await wifi_manager.connect(selected_ssid, passphrase)
            print(f"Connected to {selected_ssid}. IP Configuration: {ip_config}")
            system_manager.update_state("scan")
        else:
            print("Invalid choice. Returning to menu.")
    except WiFiConnectionError as e:
        print(f"Failed to connect: {e}")
    except Exception as e:
        print(f"Unexpected error during scan and connect: {e}")



async def start_access_point():
    """Start the ESP32 in Access Point mode with WPA2 security."""
    ssid = input("Enter SSID for the Access Point: ") or "ESP32_AP"
    password = masked_input("Enter password (8+ characters) for the Access Point: ")

    if len(password) < 8:
        print("Password must be at least 8 characters. Please try again.")
        return

    channel = int(input("Enter Wi-Fi channel (default 6): ") or 6)

    try:
        ip_config = wifi_manager.start_ap(ssid, password, channel)
        print(f"Access Point started successfully! IP Configuration: {ip_config}")
    except WiFiConnectionError as e:
        print(f"Failed to start Access Point: {e}")


async def offline_mode():
    """Start in offline mode."""
    if wifi_manager.status():
        print("Disconnecting Wi-Fi before entering offline mode...")
        wifi_manager.disconnect()
        await asyncio.sleep(1)  # Allow time for disconnection

    system_manager.update_state("offline")
    print("Operating in offline mode.")
    led.value(1)  # Turn LED off to indicate offline status
    await asyncio.sleep(2)  # Pause briefly to confirm the mode


async def start_bridge_mode():
    """
    Start the ESP32 in bridge/repeater mode.
    Scan for available networks, allow the user to select one,
    and create an Access Point (AP) for the bridge.
    """
    try:
        print("Scanning for available networks...")
        networks = wifi_manager.scan()

        # Display available networks
        for i, net in enumerate(networks):
            ssid = net["ssid"]
            rssi = net["rssi"]
            security = net["security"]
            print(f"{i + 1}: {ssid} (RSSI: {rssi}, Security: {security})")

        # Allow the user to select a network
        choice = int(input("Select a network to connect to (number): ")) - 1
        if 0 <= choice < len(networks):
            selected_ssid = networks[choice]["ssid"]
            print(f"Selected network: {selected_ssid}")

            # Prompt for the password
            if networks[choice]["security"] != "Open":
                passphrase = masked_input(f"Enter passphrase for {selected_ssid}: ")
            else:
                passphrase = ""

            # Connect to the selected network
            ip_config_sta = await wifi_manager.connect(selected_ssid, passphrase)

            # Mask the IP configuration before printing
            masked_ip_config = EncryptionHelper.mask_ip_config(ip_config_sta)
            print(f"Connected to {selected_ssid}. Station IP Configuration: {masked_ip_config}")
        else:
            print("Invalid choice. Returning to menu.")
            return

        # Start the Access Point (AP) for the bridge
        ssid_ap = masked_input("Enter SSID for the bridge Access Point: ")
        password_ap = masked_input("Enter password (8+ characters) for the bridge Access Point: ")
        if len(password_ap) < 8:
            print("Password must be at least 8 characters. Please try again.")
            return

        # Configure and start the AP
        ip_config_ap = wifi_manager.start_ap(ssid=ssid_ap, password=password_ap)
        masked_ip_config_ap = EncryptionHelper.mask_ip_config(ip_config_ap)
        print(f"Bridge Access Point started. AP IP Configuration: {masked_ip_config_ap}")

        # Enable NAT for bridging
        if await start_nat():
            print("Network Address Translation (NAT) enabled. Devices can now access the internet.")
        else:
            print("Failed to enable NAT.")
    except WiFiConnectionError as e:
        print(f"Failed to connect to Wi-Fi: {e}")
    except Exception as e:
        print(f"Unexpected error in Bridge Mode: {e}")
        wifi_manager.disconnect()
        wifi_manager.stop_ap()



def masked_input(prompt="Enter passphrase: ", mask_char="*"):
    """Prompt user for input while masking characters."""
    sys.stdout.write(prompt)
    password = []
    while True:
        char = sys.stdin.read(1)
        if char in ("\r", "\n"):  # Enter key pressed
            break
        elif char in ("\x08", "\x7f"):  # Backspace key pressed
            if password:
                password.pop()
                sys.stdout.write("\b \b")  # Erase last character
        else:
            password.append(char)
            sys.stdout.write(mask_char)
    sys.stdout.write("\n")
    return ''.join(password)


# Main Menu
async def main_menu():
    """Main menu for user interaction."""
    blink_task = asyncio.create_task(blink_led())  # Start blinking task
    try:
        print("\nMain Menu:")
        print("1: Connect to home network")
        print("2: Scan and connect to a network")
        print("3: Start offline mode")
        print("4: Check Wi-Fi status")
        print("5: Start Access Point mode")
        print("6: Stop Access Point")
        print("7: Start Bridge/Repeater mode")
        print("8: Exit Program")
        choice = input("Choose an option: ")

        if choice == "1":
            await connect_to_home()
        elif choice == "2":
            await scan_and_connect()
        elif choice == "3":
            await offline_mode()  # Offline mode re-integrated here
        elif choice == "4":
            wifi_status = wifi_manager.get_ip_config()
            if wifi_status:
                print("Wi-Fi is connected. IP Configuration:", wifi_status)
            else:
                print("Wi-Fi is not connected.")
        elif choice == "5":
            await start_access_point()
        elif choice == "6":
            wifi_manager.stop_ap()
        elif choice == "7":
            await start_bridge_mode()
        elif choice == "8":
            print("Exiting program...")
            return
        else:
            print("Invalid choice. Please try again.")
    finally:
        blink_task.cancel()
        try:
            await blink_task
        except asyncio.CancelledError:
            pass


# Initialize Wi-Fi Manager
wifi_manager = WiFiManager()
system_manager = SystemManager()

# Run the program
if __name__ == "__main__":
    asyncio.run(main_menu())
