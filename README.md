
#  Image Steganography Tool (LSB-based)

##  Overview
This project is a Python-based GUI tool that allows users to hide and extract secret messages within digital images using the **Least Significant Bit (LSB)** steganography technique. It is designed with a simple, intuitive interface using **Tkinter**, making it suitable for both beginners and those interested in information security.

---

##  Abstract
In an era where data privacy is crucial, steganography provides a creative method for secure communication. This tool leverages the LSB method to embed textual messages into image files, without altering their visual quality. With support for formats like **PNG** and **BMP**, and a user-friendly GUI, the tool demonstrates the real-world application of hiding information in plain sight. It serves as a foundation for learning data hiding and digital security in a simple and interactive way.

---

##  Features
-  Hide secret **text messages** inside images
-  Extract hidden messages from stego-images
-  Simple and user-friendly **Tkinter GUI**
-  Supports lossless formats like **PNG** and **BMP**
-  Optional drag-and-drop support and encryption (future scope)

---

##  Technologies Used
- Python 3.x  
- Pillow (PIL) – for image processing  
- Tkinter – for building the GUI

---

##  How It Works

###  Encoding Process
- Converts the message into binary
- Hides each bit in the **least significant bits** of image pixel values (RGB)
- Appends a delimiter (`1111111111111110`) to indicate the end of the message

###  Decoding Process
- Extracts the LSBs from each pixel
- Reconstructs the binary message until the delimiter is found
- Converts the binary back into readable text

---

## Installation

###  Install Dependencies
```bash
pip install pillow
```

---

##  Running the Tool

Assuming your file is named `python.py`, run:

```bash
python3 python.py
```

## 🖱️ GUI Usage

- **Hide Message**:  
  Select an image → Type your message → Save stego-image  
- **Extract Message**:  
  Open a stego-image → Extract the hidden message into the text box

---


##  Conclusion
This project demonstrates the effective use of steganography for secure message hiding using the LSB method. The implementation is lightweight, easy to use, and visually transparent. It offers an engaging way to explore basic information security concepts and lays the groundwork for more advanced features like encryption and file hiding.

---

##  Future Enhancements
-  Password-protected encryption for secure messages
-  Ability to hide and extract files, not just text
-  Drag-and-drop support for better UX
-  Support for more image formats (e.g., JPG with caution)

---


