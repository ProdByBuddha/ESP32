
# ESP32 Wi-Fi Manager and System Control Module

This project provides a comprehensive module to manage Wi-Fi connections, system state, and network configurations on an ESP32 microcontroller. It supports a variety of Wi-Fi modes and functionalities, such as connecting to existing networks, creating Access Points (AP), enabling Network Address Translation (NAT) for bridge/repeater mode, and managing system configurations persistently.

## Features

- **Wi-Fi Station Mode**: Connect to existing Wi-Fi networks.
- **Access Point Mode**: Set up a secured Wi-Fi network with WPA2.
- **Bridge/Repeater Mode**: Create an Access Point while connecting to another Wi-Fi network using NAT.
- **System State Management**: Persist system states (e.g., online, offline) to configuration files.
- **Encrypted Configuration**: Secure sensitive data using AES encryption.
- **LED Status Indication**: Visual feedback for system states (e.g., idle, connected, error).
- **Error Handling**: Custom exception handling for Wi-Fi connection errors.
- **User Input Masking**: Securely mask input for sensitive data, such as passwords.

---

## Table of Contents

1. [Installation](#installation)
2. [Usage](#usage)
3. [Features in Detail](#features-in-detail)
4. [Configuration Files](#configuration-files)
5. [Dependencies](#dependencies)
6. [Contributing](#contributing)
7. [License](#license)

---

## Installation

1. Clone this repository onto your ESP32 file system.
2. Ensure all dependencies are installed (see [Dependencies](#dependencies)).
3. Upload the files to the ESP32 using a compatible IDE (e.g., Thonny, uPyCraft, or rshell).
4. Connect to the ESP32 via a serial terminal to interact with the system.

---

## Usage

### Running the Module

1. Run the script:

   ```python

   import main
   asyncio.run(main.main_menu())

   ```

2. Use the interactive menu to perform actions:
   - `1`: Connect to a pre-configured home network.
   - `2`: Scan and connect to available networks.
   - `3`: Switch to offline mode.
   - `4`: Check Wi-Fi status.
   - `5`: Start an Access Point.
   - `6`: Stop the Access Point.
   - `7`: Start Bridge/Repeater mode.
   - `8`: Exit the program.

---

## Features in Detail

### 1. **Wi-Fi Station Mode**

- Connect to existing Wi-Fi networks using the `connect_to_home` or `scan_and_connect` functions.
- Persistent configuration files store network details securely using AES encryption.

### 2. **Access Point Mode**

- Create a secure Wi-Fi network using WPA2.
- Configure the SSID, password, and channel.
- View the Access Point's IP configuration.

### 3. **Bridge/Repeater Mode**

- Simultaneously connect to a Wi-Fi network and create an AP for devices to share the connection.
- Enable Network Address Translation (NAT) to bridge devices to the internet.

### 4. **System State Management**

- Save system states (e.g., `online`, `offline`) to a JSON configuration file.
- Automatically restore the last saved state on startup.

### 5. **Encrypted Configuration**

- Use AES encryption for sensitive data such as Wi-Fi passwords.
- Securely decrypt configurations on demand using a master passphrase.

### 6. **LED Status Indication**

- Indicate system states visually with an onboard LED:
  - `Idle`: Blink at 0.25-second intervals.
  - `Connected`: Blink at 1-second intervals.
  - `Error`: Quick triple blinks.

---

## Configuration Files

### 1. `system_config.json`

Stores system states persistently:

```json
{
  "state": "offline"
}

```

### 2. `keys.enc`

Encrypted file storing sensitive AES keys. Ensure this file is protected.

### 3. `config.txt.enc`

Encrypted Wi-Fi configuration file:

```python

SSID=YourWiFiNetwork
PASSWORD=YourPassword

```

---

## Dependencies

This module uses the following libraries:

- `uasyncio`: Asynchronous I/O for multitasking.
- `network`: Wi-Fi network interface.
- `machine`: Hardware control interface for the ESP32.
- `ucryptolib`: AES encryption for sensitive data.
- `ujson`: Lightweight JSON parsing for configurations.

Ensure these dependencies are available in your ESP32 MicroPython firmware. Update your firmware if required.

---

## Example Interaction

After running the module, you’ll see the following menu:

```text
Main Menu:
1: Connect to home network
2: Scan and connect to a network
3: Start offline mode
4: Check Wi-Fi status
5: Start Access Point mode
6: Stop Access Point
7: Start Bridge/Repeater mode
8: Exit Program
Choose an option:
```

### Connecting to Home Network

1. Select option `1`.
2. Enter the master passphrase to unlock your encrypted configuration.
3. The system connects to the stored Wi-Fi SSID and displays its IP configuration.

---

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a feature branch:

   ```bash

   git checkout -b feature-name

   ```

3. Commit your changes:

   ```bash
   git commit -m "Add a new feature"

   ```

4. Push the branch:

   ```bash
   git push origin feature-name

   ```

5. Submit a pull request.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---
