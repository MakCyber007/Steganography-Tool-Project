# LSB Steganography Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/Python-3.13.5-blue?logo=python)](https://www.python.org/)
[![Tk Version](https://img.shields.io/badge/Tkinter-8.6-lightgrey)](https://docs.python.org/3/library/tkinter.html)

## 💡 Overview

The **LSB Steganography Tool** is a lightweight, user-friendly Python application that allows you to **hide secret text messages or files within image files** and subsequently **extract them**. It utilizes the Least Significant Bit (LSB) steganography technique, making the hidden data visually imperceptible.

### Key Features:

* **Data Concealment:** Embed text or any file type into PNG or BMP images.
* **Data Extraction:** Recover hidden text or files from PNG images.
* **Intuitive GUI:** Built with Tkinter for ease of use.
* **Drag-and-Drop Support:** Seamlessly select input and output files.
* **Lossless Operation:** Ensures data integrity by saving steganographic images as PNG.

## 🚀 Getting Started

To use the LSB Steganography Tool:


1.  **Choose your preferred method:**

    * **Windows Installer (Recommended for most users):**
        Download `Steganography Tool Easy Setup.exe`. This provides a guided installation, creating desktop and start menu shortcuts for convenience.
    * **Portable Windows Executable:**
        Download `Steganography Tool.exe`. Run this file directly; no installation is needed, but shortcuts are not created. Recommended for technical users.
    * **Python Script:**
        Requires Python and necessary libraries installed. This offers granular control and allows code modification. Download `Steganography Tool.py`.
       * **Install Python**
        * **Install Dependencies:**
            ```bash
            pip install Pillow tkinterdnd2
            ```
        * **Run the script:**
            ```bash
            python "Steganography Tool.py"
            ```

## 🛠️ Tools Used

This project was developed using:

* **Python:** 3.13.5 (Primary language for logic and GUI).
* **Pillow (PIL Fork):** For image manipulation (pixel access, saving lossless formats).
* **Tkinter:** TkVersion: 8.6, TclVersion: 8.6 (Python's standard GUI toolkit for building the user interface).
* **tkinterdnd2:** A Python wrapper for enhanced drag-and-drop functionality.
* **PyInstaller:** Used for packaging the Python application into standalone Windows executables.
* **Inno Setup:** Utilized for creating a professional Windows installer.

## 📜 Project Files & Deliverables

This repository contains the following key files:

1.  `README.md`: The file you are currently reading.
2.  `Official Documentation.pdf`: Showcases the application's usage and 'know-how'.
3.  `LICENSE.txt`: The project's licensing information.
4.  `Steganography Tool Easy Setup.exe`: **Windows exclusive** – Recommended installer for easy setup and shortcuts.
5.  `Steganography Tool.exe`: **Windows exclusive** – Portable executable, no installation, runs directly.
6.  `Steganography Tool.py`: The main Python source code. Requires Python and dependencies.
7.  `Source-code.txt`: A separate text file containing the complete source code for easy distribution and review.
8.  `Project Report.pdf`: The official report submitted for the internship project.

## ✍️ Author's Note

This project was inspired by a real-world incident where cybercriminals exploited maliciously crafted image forwards on a communication app to exfiltrate financial data, leading to fraudulent online banking transactions. This event deeply influenced my initial journey into Information Security. Coincidentally, during my internship at ELEVATE LABS, steganography was listed among the assigned projects. This tool represents the culmination of my internship project.

I've decided to release it as an open-source, freeware application to encourage further use and enhancements. While numerous steganography tools exist, I believe a **very simple, lightweight, image-only (PNG/BMP) tool** could be valuable for:
* Educational purposes and personal learning (like my own journey).
* Potentially, future penetration testing and red teaming engagements.

---

**_Disclosure_**: This tool's initial coding and development involved the use of Generative AI. As a cybersecurity student well-versed in scripting but not a professional programmer, I have diligently debugged the code to the best of my abilities.

Community contributions are highly encouraged: feel free to enhance code efficiency, conduct software quality analysis, identify and fix bugs, test the application thoroughly, address security vulnerabilities, improve the user interface, or add new features.

---

## 🤝 Contributing

Contributions are welcome! If you have suggestions for improvements, feature requests, or bug reports, please open an issue or submit a pull request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) file for details.
