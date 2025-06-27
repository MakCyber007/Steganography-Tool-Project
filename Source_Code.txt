import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image
import os
import tkinterdnd2 as TkinterDnD

# --- Core Steganography Logic (LSB Implementation) ---

def text_to_binary(text):
    """
    Converts a string of text into its binary representation.
    Each character is converted to its 8-bit ASCII/Unicode binary equivalent.
    """
    return ''.join(format(ord(char), '08b') for char in text)

def binary_to_text(binary_string):
    """
    Converts a binary string back into text.
    It processes the binary string in 8-bit chunks and converts each chunk
    back into its corresponding character.
    """
    text = ''
    # Ensure binary_string length is a multiple of 8 to avoid errors during conversion
    # Truncate any incomplete last byte.
    binary_string = binary_string[:len(binary_string) - (len(binary_string) % 8)]
    for i in range(0, len(binary_string), 8):
        byte = binary_string[i:i+8]
        # Convert the 8-bit binary string to an integer, then to a character
        text += chr(int(byte, 2))
    return text

def file_to_bytes(file_path):
    """
    Reads a file from the given path and returns its content as bytes.
    This is used when hiding an entire file.
    """
    try:
        with open(file_path, 'rb') as f:
            return f.read(), None # Return file content bytes and no error message
    except FileNotFoundError:
        return None, f"Error: File not found at {file_path}"
    except Exception as e:
        return None, f"Error reading file: {e}"

def bytes_to_file(binary_string, output_file_path):
    """
    Converts a binary string to a byte array and saves it to a file.
    This is used when extracting a hidden file.
    """
    try:
        # Pad the binary string with leading zeros if its length is not a multiple of 8.
        # This ensures that `int(byte, 2)` for each 8-bit chunk works correctly.
        padding_needed = 8 - (len(binary_string) % 8)
        if padding_needed != 8: # Only pad if not already a multiple of 8
            binary_string = '0' * padding_needed + binary_string

        byte_array = bytearray()
        for i in range(0, len(binary_string), 8):
            byte = int(binary_string[i:i+8], 2)
            byte_array.append(byte)

        with open(output_file_path, 'wb') as f:
            f.write(byte_array)
        return True, f"File successfully extracted to {output_file_path}"
    except Exception as e:
        return False, f"Error saving extracted file: {e}"

def hide_data_in_image(image_path, data, output_path):
    """
    Hides data (text or binary content) within an image using LSB steganography.
    It modifies the least significant bit of each color channel (R, G, B, A)
    in the image to embed the binary data.
    """
    try:
        # Open the image and convert it to RGBA mode.
        # RGBA ensures we have an alpha channel to potentially hide more data,
        # and consistency across different input image types.
        img = Image.open(image_path).convert("RGBA")
    except FileNotFoundError:
        return False, f"Error: Input image not found at {image_path}"
    except Exception as e:
        return False, f"Error opening image: {e}. Please ensure it's a valid image file."

    width, height = img.size
    pixels = img.load() # Load pixel access object for direct pixel manipulation

    # Convert the input data (string or bytes) into a single binary string
    if isinstance(data, str): # If data is text
        binary_data = ''.join(format(ord(char), '08b') for char in data)
    elif isinstance(data, bytes): # If data is file content (bytes)
        binary_data = ''.join(format(byte, '08b') for byte in data)
    else:
        return False, "Internal Error: Data must be a string (text) or bytes (file content)."

    # Append a unique delimiter to mark the end of the hidden data.
    # This delimiter is crucial for correctly extracting the message later.
    # '1111111111111110' is a 16-bit sequence unlikely to appear naturally in short messages.
    delimiter = '1111111111111110'
    binary_data += delimiter

    data_len = len(binary_data)
    # Calculate the maximum number of bits that can be hidden in the image.
    # Each pixel has 4 channels (R, G, B, A), and each channel can hide 1 bit.
    max_bits_possible = width * height * 4
    if data_len > max_bits_possible:
        return False, f"Error: Data ({data_len} bits) is too large to hide in this image (max {max_bits_possible} bits available)."

    data_index = 0
    # Iterate over each pixel and its color channels to embed data
    for y in range(height):
        for x in range(width):
            r, g, b, a = pixels[x, y] # Get current RGBA values of the pixel

            # Modify the LSB of each channel if there's data left to embed
            if data_index < data_len:
                # `(r & 0xFE)` clears the LSB (sets it to 0).
                # `| int(binary_data[data_index])` sets the LSB to the current bit from `binary_data`.
                r = (r & 0xFE) | int(binary_data[data_index])
                data_index += 1
            if data_index < data_len:
                g = (g & 0xFE) | int(binary_data[data_index])
                data_index += 1
            if data_index < data_len:
                b = (b & 0xFE) | int(binary_data[data_index])
                data_index += 1
            if data_index < data_len:
                a = (a & 0xFE) | int(binary_data[data_index])
                data_index += 1

            # Update the pixel with the modified RGBA values
            pixels[x, y] = (r, g, b, a)

            if data_index >= data_len:
                break # All data has been embedded, exit loops
        if data_index >= data_len:
            break

    try:
        # Save the modified image. PNG is a lossless format, which is critical
        # for LSB steganography as lossy compression (like JPEG) would destroy
        # the subtle LSB changes.
        img.save(output_path, "PNG")
        return True, f"Data successfully hidden in {output_path}"
    except Exception as e:
        return False, f"Error saving image: {e}. Please check output path and permissions."

def extract_data_from_image(image_path):
    """
    Extracts hidden data from an image by reading the LSB of each color channel.
    It stops extraction when the predefined delimiter is found.
    """
    try:
        # Open the image (assume it was saved in RGBA for consistent extraction)
        img = Image.open(image_path).convert("RGBA")
    except FileNotFoundError:
        return None, f"Error: Image not found at {image_path}"
    except Exception as e:
        return None, f"Error opening image: {e}. Please ensure it's a valid image file."

    width, height = img.size
    pixels = img.load() # Load pixel access object

    binary_data = ""
    delimiter = '1111111111111110'
    delimiter_len = len(delimiter)

    # Iterate over each pixel and its color channels to extract LSBs
    for y in range(height):
        for x in range(width):
            r, g, b, a = pixels[x, y]

            # Extract the LSB from each channel using bitwise AND with 1
            binary_data += str(r & 1)
            binary_data += str(g & 1)
            binary_data += str(b & 1)
            binary_data += str(a & 1)

            # Check if the extracted binary data ends with the delimiter.
            # If it does, the message is complete.
            if binary_data.endswith(delimiter):
                # Remove the delimiter from the extracted data before returning
                return binary_data[:-delimiter_len], "Data extracted successfully."
    # If the loops complete and the delimiter is not found,
    # it means no valid hidden message or a corrupted image.
    return None, "Delimiter not found or no data extracted from the image. It might not contain hidden data or is corrupted."

# --- Tkinter GUI Implementation ---

class SteganographyTool:
    """
    GUI application for hiding and extracting data using LSB steganography.
    """
    def __init__(self, master):
        self.master = master
        master.title("LSB Steganography Tool")
        master.geometry("800x600") # Set initial window size
        master.resizable(False, False) # Prevent resizing for simpler layout management

        # Configure styling for ttk widgets for a modern look
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f0f0") # Light grey background
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("TButton", font=("Arial", 10, "bold"), padding=5)
        self.style.configure("TEntry", font=("Arial", 10), padding=3)
        self.style.configure("TText", font=("Arial", 10), padding=3)
        self.style.map("TButton", background=[('active', '#e0e0e0')]) # Hover effect for buttons

        # Tkinter variables to hold paths and messages
        self.input_image_path = tk.StringVar()
        self.output_image_path = tk.StringVar()
        self.message_to_hide = tk.StringVar()
        self.hidden_file_path = tk.StringVar()
        self.extracted_file_path = tk.StringVar()
        self.extraction_image_path = tk.StringVar()
        self.extracted_data_for_file = None # To temporarily hold extracted binary data for saving

        # Create a Notebook (tabbed interface)
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(pady=10, expand=True, fill="both")

        # Create individual tabs
        self.hide_tab = ttk.Frame(self.notebook)
        self.extract_tab = ttk.Frame(self.notebook)

        # Add tabs to the notebook
        self.notebook.add(self.hide_tab, text="Hide Data")
        self.notebook.add(self.extract_tab, text="Extract Data")

        # Populate each tab with its widgets
        self.create_hide_tab() # Call to create hide tab UI
        self.create_extract_tab() # Call to create extract tab UI

        # --- TkinterDnD Integration ---
        # The TkinterDnD.Tk() object automatically handles the underlying tkdnd package loading.
        # We just need to register drop targets and bind to the <<Drop>> event.
        try:
            self._setup_dnd()
            print("Drag and drop enabled via tkinterdnd2.")
        except Exception as e:
            print(f"Warning: Drag and drop setup failed with tkinterdnd2. Error: {e}")
            messagebox.showwarning("Drag & Drop Warning",
                                   f"Drag and drop functionality could not be initialized.\n"
                                   f"Error: {e}\n"
                                   f"Please ensure the 'tkinterdnd2' library is correctly installed "
                                   f"and compatible with your Python/Tkinter version.")

    def create_hide_tab(self):
        """Builds the UI for the 'Hide Data' tab."""
        # Frame for input image selection
        image_frame = ttk.LabelFrame(self.hide_tab, text="1. Select Input Image (PNG/BMP)")
        image_frame.pack(pady=10, padx=10, fill="x")

        ttk.Label(image_frame, text="Input Image Path:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        # Store the Entry widget as an instance attribute for DND binding
        self.input_image_path_entry = ttk.Entry(image_frame, textvariable=self.input_image_path, width=50, state="readonly")
        self.input_image_path_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(image_frame, text="Browse", command=self.browse_input_image).grid(row=0, column=2, padx=5, pady=5)

        # Frame for data type selection (Text/File)
        data_type_frame = ttk.LabelFrame(self.hide_tab, text="2. Choose Data to Hide")
        data_type_frame.pack(pady=10, padx=10, fill="x")

        self.hide_choice = tk.StringVar(value="text") # Default to hiding text
        ttk.Radiobutton(data_type_frame, text="Hide Text Message", variable=self.hide_choice, value="text", command=self.toggle_hide_options).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Radiobutton(data_type_frame, text="Hide A File", variable=self.hide_choice, value="file", command=self.toggle_hide_options).grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # Widgets for hiding text
        self.text_label = ttk.Label(data_type_frame, text="Enter Message:")
        self.text_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.message_entry = ttk.Entry(data_type_frame, textvariable=self.message_to_hide, width=60)
        self.message_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5)

        # Widgets for hiding a file (IMPORTANT: Create these before calling toggle_hide_options)
        self.file_label = ttk.Label(data_type_frame, text="Select File to Hide:")
        self.file_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        # Store this Entry widget as an instance attribute for DND binding
        self.hidden_file_path_entry = ttk.Entry(data_type_frame, textvariable=self.hidden_file_path, width=50, state="readonly")
        self.hidden_file_path_entry.grid(row=2, column=1, padx=5, pady=5)
        self.file_browse_button = ttk.Button(data_type_frame, text="Browse File", command=self.browse_file_to_hide)
        self.file_browse_button.grid(row=2, column=2, padx=5, pady=5)

        # Call toggle_hide_options *after* all related widgets have been created
        self.toggle_hide_options()

        # Frame for output image path selection
        output_frame = ttk.LabelFrame(self.hide_tab, text="3. Save Output Image As (PNG recommended)")
        output_frame.pack(pady=10, padx=10, fill="x")

        ttk.Label(output_frame, text="Output Image Path:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(output_frame, textvariable=self.output_image_path, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(output_frame, text="Save Location", command=self.browse_output_image).grid(row=0, column=2, padx=5, pady=5)

        # Button to trigger the hiding process
        ttk.Button(self.hide_tab, text="Hide Data in Image", command=self.hide_data).pack(pady=20)


    def create_extract_tab(self):
        """Builds the UI for the 'Extract Data' tab."""
        # Frame for selecting image to extract from
        image_frame = ttk.LabelFrame(self.extract_tab, text="1. Select Image with Hidden Data")
        image_frame.pack(pady=10, padx=10, fill="x")

        ttk.Label(image_frame, text="Input Image Path:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        # Store this Entry widget as an instance attribute for DND binding
        self.extraction_image_path_entry = ttk.Entry(image_frame, textvariable=self.extraction_image_path, width=50, state="readonly")
        self.extraction_image_path_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(image_frame, text="Browse", command=self.browse_extraction_image).grid(row=0, column=2, padx=5, pady=5)

        # Button to trigger the extraction process
        ttk.Button(self.extract_tab, text="Extract Data from Image", command=self.extract_data).pack(pady=20)

        # Frame for displaying extracted data and saving extracted files
        extracted_frame = ttk.LabelFrame(self.extract_tab, text="2. Extracted Data")
        extracted_frame.pack(pady=10, padx=10, fill="both", expand=True)

        ttk.Label(extracted_frame, text="Extracted Text Preview:").grid(row=0, column=0, padx=5, pady=5, sticky="nw")
        self.extracted_text_display = tk.Text(extracted_frame, wrap="word", height=8, width=60)
        self.extracted_text_display.grid(row=0, column=1, columnspan=2, padx=5, pady=5)
        self.extracted_text_display.config(state="disabled", background="#e9e9e9") # Make it read-only and slightly greyed out

        ttk.Label(extracted_frame, text="Save Extracted File As:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(extracted_frame, textvariable=self.extracted_file_path, width=50).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(extracted_frame, text="Save Extracted File", command=self.save_extracted_file).grid(row=1, column=2, padx=5, pady=5)

    def toggle_hide_options(self):
        """
        Switches the visibility of text hiding widgets vs. file hiding widgets
        based on the radio button selection in the 'Hide Data' tab.
        """
        choice = self.hide_choice.get()
        if choice == "text":
            # Show text widgets
            self.text_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
            self.message_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5)
            # Hide file widgets
            self.file_label.grid_forget()
            self.hidden_file_path_entry.grid_forget() # Use the specific entry widget
            self.file_browse_button.grid_forget()
        else: # choice == "file"
            # Hide text widgets
            self.text_label.grid_forget()
            self.message_entry.grid_forget()
            # Show file widgets
            self.file_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
            self.hidden_file_path_entry.grid(row=2, column=1, padx=5, pady=5) # Use the specific entry widget
            self.file_browse_button.grid(row=2, column=2, padx=5, pady=5)

    def browse_input_image(self):
        """Opens a file dialog for selecting the input image to hide data in."""
        file_path = filedialog.askopenfilename(
            title="Select Image to Hide Data In",
            filetypes=[("Image Files", "*.png *.bmp"), ("All Files", "*.*")]
        )
        if file_path:
            self.input_image_path.set(file_path)

    def browse_output_image(self):
        """Opens a file dialog for specifying the output path for the stego-image."""
        file_path = filedialog.asksaveasfilename(
            title="Save Steganographic Image As",
            defaultextension=".png", # Ensure it saves as PNG for lossless embedding
            filetypes=[("PNG files", "*.png"), ("All Files", "*.*")]
        )
        if file_path:
            self.output_image_path.set(file_path)

    def browse_file_to_hide(self):
        """Opens a file dialog for selecting the file to hide."""
        file_path = filedialog.askopenfilename(title="Select File to Hide")
        if file_path:
            self.hidden_file_path.set(file_path)

    def browse_extraction_image(self):
        """Opens a file dialog for selecting the image to extract data from."""
        file_path = filedialog.askopenfilename(
            title="Select Image to Extract Data From",
            filetypes=[("PNG files", "*.png"), ("All Files", "*.*")] # Recommend PNG
        )
        if file_path:
            self.extraction_image_path.set(file_path)

    def hide_data(self):
        """
        Handles the 'Hide Data' button click event.
        Gathers inputs, calls the core hiding function, and displays results.
        """
        image_path = self.input_image_path.get()
        output_path = self.output_image_path.get()
        hide_type = self.hide_choice.get()
        data_to_hide = None # Initialize to None

        # Input validation for paths
        if not image_path:
            messagebox.showerror("Input Error", "Please select an input image.")
            return
        if not output_path:
            messagebox.showerror("Input Error", "Please specify an output image path.")
            return

        # Prepare data based on selected type (text or file)
        if hide_type == "text":
            message = self.message_to_hide.get()
            if not message:
                messagebox.showerror("Input Error", "Please enter a message to hide.")
                return
            data_to_hide = message
        elif hide_type == "file":
            file_path = self.hidden_file_path.get()
            if not file_path:
                messagebox.showerror("Input Error", "Please select a file to hide.")
                return
            # Read file content as bytes
            data_to_hide, error_msg = file_to_bytes(file_path)
            if error_msg: # If there was an error reading the file
                messagebox.showerror("File Read Error", error_msg)
                return
            if data_to_hide is None: # Should not happen if error_msg is handled, but as a safeguard
                messagebox.showerror("File Read Error", "Failed to read the file content.")
                return

        # Call the core steganography function
        success, msg = hide_data_in_image(image_path, data_to_hide, output_path)

        # Display results to the user
        if success:
            messagebox.showinfo("Success", msg)
        else:
            messagebox.showerror("Hiding Failed", msg)

    def extract_data(self):
        """
        Handles the 'Extract Data' button click event.
        Gathers input image path, calls the core extraction function,
        and displays or prepares the extracted data for saving.
        """
        image_path = self.extraction_image_path.get()
        if not image_path:
            messagebox.showerror("Input Error", "Please select an image to extract data from.")
            return

        # Clear previous extraction results
        self.extracted_text_display.config(state="normal")
        self.extracted_text_display.delete(1.0, tk.END)
        self.extracted_text_display.config(state="disabled")
        self.extracted_data_for_file = None # Clear stored binary data

        # Call the core extraction function
        extracted_binary_data, msg = extract_data_from_image(image_path)

        if extracted_binary_data:
            # Store the raw binary data for potential file saving
            self.extracted_data_for_file = extracted_binary_data

            # Attempt to interpret extracted data as text for preview
            try:
                extracted_text = binary_to_text(extracted_binary_data)
                # Display only a preview of the text (e.g., first 500 characters)
                preview_text = extracted_text if len(extracted_text) < 500 else extracted_text[:500] + "..."
                self.extracted_text_display.config(state="normal")
                self.extracted_text_display.insert(tk.END, preview_text)
                self.extracted_text_display.config(state="disabled")
                messagebox.showinfo("Extraction Success", msg + "\n\nIf this looks like garbled text, it might be a file. Use 'Save Extracted File' button.")
            except Exception:
                # If conversion to text fails, it's likely binary file data
                self.extracted_text_display.config(state="normal")
                self.extracted_text_display.insert(tk.END, "Could not interpret as text. It might be a file. Use 'Save Extracted File' button to save it.")
                self.extracted_text_display.config(state="disabled")
                messagebox.showinfo("Extraction Success", msg + "\n\nExtracted data appears to be a file. Use 'Save Extracted File' button.")
        else:
            messagebox.showerror("Extraction Failed", msg)
            # Ensure text display is empty and disabled on failure
            self.extracted_text_display.config(state="normal")
            self.extracted_text_display.delete(1.0, tk.END)
            self.extracted_text_display.config(state="disabled")

    def save_extracted_file(self):
        """
        Handles the 'Save Extracted File' button click event.
        Prompts the user for a save location and saves the previously extracted
        binary data (if any) as a file.
        """
        if self.extracted_data_for_file: # Check if there's data to save
            output_file_path = filedialog.asksaveasfilename(
                title="Save Extracted File As",
                defaultextension="" # Allow user to specify extension
            )
            if output_file_path:
                success, msg = bytes_to_file(self.extracted_data_for_file, output_file_path)
                if success:
                    messagebox.showinfo("File Save Success", msg)
                else:
                    messagebox.showerror("File Save Failed", msg)
            else:
                messagebox.showwarning("Save Cancelled", "File save operation cancelled by user.")
        else:
            messagebox.showwarning("No Data to Save", "No data has been extracted yet, or the extracted data was already displayed as text.")

    # --- Drag-and-Drop Handlers (Enabled if TkinterDnD loads) ---
    def _setup_dnd(self):
        """
        Sets up drag-and-drop bindings using tkinterdnd2's direct methods.
        This is called only if the TkinterDnD root object is successfully created.
        """
        try:
            # Register specific Entry widgets as drop targets with specific handlers
            self.input_image_path_entry.drop_target_register(TkinterDnD.DND_FILES)
            self.input_image_path_entry.dnd_bind('<<Drop>>', self._handle_input_image_entry_drop)

            self.hidden_file_path_entry.drop_target_register(TkinterDnD.DND_FILES)
            self.hidden_file_path_entry.dnd_bind('<<Drop>>', self._handle_hidden_file_entry_drop)

            self.extraction_image_path_entry.drop_target_register(TkinterDnD.DND_FILES)
            self.extraction_image_path_entry.dnd_bind('<<Drop>>', self._handle_extraction_image_entry_drop)

            # Register general tab areas as drop targets (fallback for drops not hitting specific entries)
            self.hide_tab.drop_target_register(TkinterDnD.DND_FILES)
            self.hide_tab.dnd_bind('<<Drop>>', self._handle_hide_tab_general_drop)

            self.extract_tab.drop_target_register(TkinterDnD.DND_FILES)
            self.extract_tab.dnd_bind('<<Drop>>', self._handle_extract_tab_general_drop)

            # Register the notebook as a global drop target (for a wider drop area)
            # This handler will route to the specific tab's general handler
            self.notebook.drop_target_register(TkinterDnD.DND_FILES)
            self.notebook.dnd_bind('<<Drop>>', self._handle_notebook_general_drop)

        except Exception as e:
            raise e # Re-raise to be caught by the __init__ error handling

    # Specific DND handlers for Entry widgets
    def _handle_input_image_entry_drop(self, event):
        """Handles drops specifically on the 'Input Image Path' entry (only images)."""
        file_paths = self.master.splitlist(event.data)
        if file_paths:
            file_path = file_paths[0].strip('{}')
            if os.path.isfile(file_path) and file_path.lower().endswith(('.png', '.bmp')):
                self.input_image_path.set(file_path)
                messagebox.showinfo("File Dropped", f"Cover image selected: {os.path.basename(file_path)}")
            else:
                messagebox.showerror("Invalid File Type", "Please drop a PNG or BMP image file for the cover image.")
        else:
            messagebox.showerror("Invalid Drop", "No valid files detected in the drop event.")

    def _handle_hidden_file_entry_drop(self, event):
        """Handles drops specifically on the 'Select File to Hide' entry (any file)."""
        file_paths = self.master.splitlist(event.data)
        if file_paths:
            file_path = file_paths[0].strip('{}')
            if os.path.isfile(file_path):
                self.hidden_file_path.set(file_path)
                messagebox.showinfo("File Dropped", f"File to hide selected: {os.path.basename(file_path)}")
            else:
                messagebox.showerror("Invalid Drop", "Please drop a valid file to hide.")
        else:
            messagebox.showerror("Invalid Drop", "No valid files detected in the drop event.")

    def _handle_extraction_image_entry_drop(self, event):
        """Handles drops specifically on the 'Input Image Path' entry for extraction (only PNG)."""
        file_paths = self.master.splitlist(event.data)
        if file_paths:
            file_path = file_paths[0].strip('{}')
            if os.path.isfile(file_path) and file_path.lower().endswith(('.png')):
                self.extraction_image_path.set(file_path)
                messagebox.showinfo("File Dropped", f"Image selected for extraction: {os.path.basename(file_path)}")
            else:
                messagebox.showerror("Invalid File Type", "Please drop a PNG image file for extraction.")
        else:
            messagebox.showerror("Invalid Drop", "No valid files detected in the drop event.")

    # General DND handlers for tab areas (fallback if not dropped on specific entries)
    def _handle_hide_tab_general_drop(self, event):
        """
        Handles general drops on the 'Hide Data' tab, defaulting to input image.
        """
        file_paths = self.master.splitlist(event.data)
        if file_paths:
            file_path = file_paths[0].strip('{}')
            if os.path.isfile(file_path) and file_path.lower().endswith(('.png', '.bmp')):
                self.input_image_path.set(file_path)
                messagebox.showinfo("File Dropped", f"Cover image selected: {os.path.basename(file_path)}")
            else:
                messagebox.showwarning("Drag & Drop",
                                       "Dropped file is not a PNG or BMP image. "
                                       "Please drop an image for the cover image, or use 'Browse' for other files.")
        else:
            messagebox.showerror("Invalid Drop", "No valid files detected in the drop event.")

    def _handle_extract_tab_general_drop(self, event):
        """
        Handles general drops on the 'Extract Data' tab, defaulting to input image.
        """
        file_paths = self.master.splitlist(event.data)
        if file_paths:
            file_path = file_paths[0].strip('{}')
            if os.path.isfile(file_path) and file_path.lower().endswith(('.png')):
                self.extraction_image_path.set(file_path)
                messagebox.showinfo("File Dropped", f"Image selected for extraction: {os.path.basename(file_path)}")
            else:
                messagebox.showwarning("Drag & Drop",
                                       "Dropped file is not a PNG image. "
                                       "Please drop a PNG image for extraction.")
        else:
            messagebox.showerror("Invalid Drop", "No valid files detected in the drop event.")

    def _handle_notebook_general_drop(self, event):
        """
        Global drop handler for the notebook, directs to the active tab's general handler.
        """
        active_tab_text = self.notebook.tab(self.notebook.select(), "text")
        if active_tab_text == "Hide Data":
            self._handle_hide_tab_general_drop(event)
        elif active_tab_text == "Extract Data":
            self._handle_extract_tab_general_drop(event)
        else:
            messagebox.showwarning("Drag & Drop", "Please switch to either 'Hide Data' or 'Extract Data' tab before dropping files.")


# --- Main Application Execution ---
if __name__ == "__main__":
    # Create the main Tkinter window using TkinterDnD.Tk()
    # This special Tk class from tkinterdnd2 enables DND capabilities.
    root = TkinterDnD.Tk()
    # Instantiate the SteganographyTool application
    app = SteganographyTool(root)
    # Start the Tkinter event loop, which makes the GUI visible and interactive
    root.mainloop()
