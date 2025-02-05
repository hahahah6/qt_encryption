# Encryption Project

## Overview

This Qt-based application provides functionalities for encryption and decryption, including key management. It allows users to encode and decode data securely using customizable secret keys.

## Project Structure

The project is organized into the following directories and files:

### Source Files

- `applink.c`: Contains logic for handling external connections.
- `decode.cpp`: Implements the decryption functionality.
- `encryption.cpp`: Implements the encryption functionality.
- `main.cpp`: Entry point for the application.
- `mainwindow.cpp`: Main window logic and UI handling.
- `secret_key.cpp`: Manages the generation and storage of secret keys.

### Header Files

- `decode.h`: Declarations for the decryption functions and classes.
- `encryption.h`: Declarations for the encryption functions and classes.
- `mainwindow.h`: Declarations for the main window components.
- `secret_key.h`: Declarations for the secret key management.

### UI Files

- `decode.ui`: UI layout for the decryption interface.
- `encryption.ui`: UI layout for the encryption interface.
- `mainwindow.ui`: Main application window layout.
- `secret_key.ui`: UI layout for managing secret keys.

### Resource Files

- `iconfile.qrc`: Resource file containing the application icons.

## Build Instructions

Follow these steps to build and run the project:

1. Ensure you have **Qt 6.8.2** and **MinGW 64-bit** installed.
2. Open the project in **Qt Creator**.
3. Configure the project using the appropriate **kit** for your system.
4. Build the project in **Debug** or **Release** mode based on your needs.

## Dependencies

This project requires the following dependencies:

- **Qt 6.8.2** for the GUI and core functionality.
- **OpenSSL** for secure encryption and decryption operations.

## License

This project is licensed under the **MIT License**.
