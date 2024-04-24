import os
import re
import time
import imghdr
import getpass
import shutil
import bcrypt
import gzip
import math
import secrets

from PIL import Image
from io import BytesIO
from Crypto.Cipher import ChaCha20, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

user_data = {}  # Dictionary to store user information
current_user = None  # Variable to store the current user

def display_banner():
    banner_file = 'ascii_banner.txt'
    with open(banner_file, 'r') as file:
        banner = file.read()
    print(banner)

def display_login_status():
    if current_user:
        print(f"\nYou are currently logged in as {current_user}.")
    else:
        print("\nNot logged in as a user. Either login or signup before use.")

def display_menu():
    print("\nMenu:")
    # Menu for registered users
    if current_user:
        print("1. Sign Out")
        print("2. Encrypt Files")
        print("3. Decrypt Files")
    # Menu when no user logged in
    else:
        print("1. Log In")
        print("2. Sign Up")
    print("4. Exit")

def calculate_password_score(password):
    score = 0

    # Length check
    length = len(password)
    if length >= 8:
        score += min(3, length // 8)  # Gradually increase score with length

    # Check for uppercase, lowercase, digits, and special characters
    if re.search(r"[A-Z]", password):
        score += 2
    if re.search(r"[a-z]", password):
        score += 2
    if re.search(r"\d", password):
        score += 2
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 2

    # Deduct score for repeating characters (e.g., "aa", "123")
    repeated_chars = len(re.findall(r"(.)\1", password))
    score -= min(3, repeated_chars)

    # Bonus score for a mix of character types
    if all(re.search(char_type, password) for char_type in [r"[A-Z]", r"[a-z]", r"\d", r"[!@#$%^&*(),.?\":{}|<>]"]):
        score += 3

    return max(0, score)  # Ensure the minimum score is 0

def login():
    global current_user
    username = input("Enter your username: ")

    if username in user_data:
        max_attempts = 3
        attempts = 0

        while not user_data[username].get('secure_deletion', False) or attempts < max_attempts:
            # Prompt for password using getpass
            password = getpass.getpass(prompt="Enter your password: ", stream=None)

            # Check if the entered password matches the stored hash
            stored_hash = user_data[username]['password_hash']
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                current_user = username
                break

            else:
                attempts += 1

                if not user_data[username].get('secure_deletion', False):
                    print("\nIncorrect password.")
                else:
                    remaining_attempts = max_attempts - attempts
                    print(f"\nIncorrect password. {remaining_attempts} {'attempts' if remaining_attempts != 1 else 'attempt'} remaining until file deletion.")

                # Once max attempts have been reached, delete all images if secure deletion is enabled
                if attempts == max_attempts and user_data[username].get('secure_deletion', False):
                    print(f"\nMax login attempts reached. Deleting all image files in the directory.")
                    secure_delete_image_files(usb_directory)
                    if os.path.exists(backup_directory):
                        shutil.rmtree(backup_directory)
                        break
    else:
        print("User not found. Please sign up.")
        signup()

# Function for the SFD process
def secure_delete_image_files(directory):
    image_files = list_image_files(directory)

    for file_name, _ in image_files:
        file_path = os.path.join(directory, file_name)
        # Overwrite the file with random data multiple times
        with open(file_path, 'wb') as file:
            file_size = os.path.getsize(file_path)
            for _ in range(3):  # Overwrite three times
                file.write(secrets.token_bytes(file_size))
        
        # After overwriting, delete the file
        os.remove(file_path)

    print("\nAll image files securely deleted.")

# Function for finding and removing all images after encryption/decryption
def delete_image_files(directory):
    image_files = list_image_files(directory)

    # Delete regular image files
    for file_name, _ in image_files:
        file_path = os.path.join(directory, file_name)
        os.remove(file_path)

    # Delete encrypted files
    encrypted_files = [file for file in os.listdir(directory) if file.startswith('encrypted_')]
    for encrypted_file in encrypted_files:
        encrypted_file_path = os.path.join(directory, encrypted_file)
        os.remove(encrypted_file_path)

    print("\nAll image files in the directory deleted.")

def signup():
    global current_user
    username = input("Enter a username: ")

    if username in user_data:
        print("Username already exists. Please choose another one.")
        return

    while True:
        # Prompt for a password and check its strength
        password = getpass.getpass(prompt="Enter your password: ", stream=None)
        password_score = calculate_password_score(password)

        # Set a threshold for password strength
        if password_score >= 5:
            break
        else:
            print("Password is too weak. Please choose a stronger password.")
            print("Password strength criteria: Minimum 8 characters, uppercase, lowercase, digit, special character")

    while True:
        confirm_password = getpass.getpass(prompt="Confirm your password: ", stream=None)

        if password == confirm_password:
            break
        else:
            print("Passwords do not match. Please try again.")
            password = getpass.getpass(prompt="Enter your password: ", stream=None)
            password_score = calculate_password_score(password)

            # Check the password strength again
            if password_score < 5:
                print("Password is too weak. Please choose a stronger password.")
                continue

    while True:
        # Prompt the user if they want to activate secure file deletion
        secure_deletion = input("\nDo you wish to activate secure file deletion? (yes/no): ").lower()

        if secure_deletion == 'yes':
            print("\nSecure file deletion activated")
            secure_deletion = True
            break
        elif secure_deletion == 'no':
            print("\nSecure file deletion not activated")
            secure_deletion = False
            break
        else:
            print("Invalid option, enter yes or no. Please try again.")

    # Hash the password
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Generate a random 32-byte key for the user
    user_key = get_random_bytes(32)
    user_data[username] = {'password_hash': password_hash, 'user_key': user_key, 'secure_deletion': secure_deletion}
    current_user = username
    print("\nSign up successful. Welcome,", username)

    # Save user data to a file immediately after signup
    with open(user_data_file, 'w') as file:
        file.write(str(user_data))

def list_image_files(directory):
    image_files = []

    # List all files in the directory
    files = os.listdir(directory)

    for file in files:
        # Get the full path of the file
        file_path = os.path.join(directory, file)

        # Check if it's a file (not a directory)
        if os.path.isfile(file_path):
            # Check if it's an image file based on the file extension
            if file.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp')):
                # Check if it's a valid image file using imghdr
                image_type = imghdr.what(file_path)
                if image_type:
                    # Add the image file to the list
                    image_files.append((file, image_type))

    return image_files

def delete_original_encrypted_files(selected_files):
    for file_name, _ in selected_files:
        encrypted_file_path = os.path.join(usb_directory, f'encrypted_{file_name}')
        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)

# Selection for compression types
def get_compression_option(algorithm):
    while True:
        print("\nCompression Options:")
        print("1. Lossless Compression")
        if algorithm != 'AES':  # Include Lossy Compression only for ChaCha20
            print("2. Lossy Compression")
        print("3. No Compression")

        choice = input("\nEnter your compression choice (1-3): ").strip()

        if choice == '2' and algorithm == 'AES':
            print("\nLossy Compression is only available for ChaCha20 encryption.")
            continue
        elif choice in ['1', '2', '3']:
            if choice == '2':
                print("\nWarning: Lossy compression may result in a reduction of image quality.")
                confirmation = input("Are you sure you want to proceed with lossy compression? (yes/no): ").lower()
                if confirmation != 'yes':
                    continue
            return int(choice)
        else:
            print("\nInvalid choice. Please enter a number 1-3.")

# gzip for lossless compression
def lossless_compress(plaintext):
    print("\nCompressing Data...")
    compressed_data = gzip.compress(plaintext)
    print("Data Compressed")
    return compressed_data

# gzip for lossless decompression
def lossless_decompress(compressed_data):
    print("\nDecompressing Data...")
    decompressed_data = gzip.decompress(compressed_data)
    print("Data Decompressed")
    return decompressed_data

# Pillow for lossy compression
def lossy_compress(plaintext, file_name):
    print("\nCompressing Data...")
    img = Image.frombytes('RGB', (1, len(plaintext) // 3), plaintext)

    # Uncomment these lines if you want to break everything for some reason
    # Resize the image to a maximum dimension of 65535 pixels
    #max_dimension = 65535
    #if img.width > max_dimension or img.height > max_dimension:
        #img.thumbnail((max_dimension, max_dimension), Image.ANTIALIAS)

    with BytesIO() as output:
        img.save(output, format = 'PNG', quality = 50)  # Use PNG format for lossy compression
        compressed_data = output.getvalue()

    # Calculate and store PSNR value in a report file
    psnr = calculate_psnr(plaintext, compressed_data)
    report_file_path = os.path.join(usb_directory, 'compression_report.txt')
    with open(report_file_path, 'a') as report_file:
        report_file.write(f"{file_name}: PSNR = {psnr:.2f}dB\n")

    print("Data Compressed")
    return compressed_data

# Pillow for lossy decompression
def lossy_decompress(compressed_data):
    print("\nDecompressing Data...")
    with BytesIO(compressed_data) as input:
        # Open the image from the compressed data
        img = Image.open(input)
        # Convert the image to bytes
        plaintext = img.tobytes()

    print("Data Decompressed")
    return plaintext

# Function for calculating PSNR of files after lossy compression
def calculate_psnr(original, compressed):
    mse = sum((o - c) ** 2 for o, c in zip(original, compressed)) / len(original)
    if mse == 0:
        return float('inf') # Mean Squared Error is 0 = no loss
    max_pixel_value = 255.0  # Assuming 8-bit images
    psnr = 20 * math.log10(max_pixel_value / math.sqrt(mse))
    return psnr

def encrypt_files(selected_files, key, algorithm):
    global current_user

    # Calculate the total size of selected files in MB before compression
    original_total_size = sum(os.path.getsize(os.path.join(usb_directory, file_name)) for file_name, _ in selected_files) / (1024 ** 2)
    print(f"\nTotal size of selected files: {original_total_size:.2f} MB")

    compression_option = get_compression_option(algorithm)

    # Create a backup directory to store unencrypted copies
    backup_directory = os.path.join(usb_directory, 'backup')
    os.makedirs(backup_directory, exist_ok=True)

    # Initialise the variable to store the new total size after compression
    new_total_size = 0

    # Check if the report file exists, if not, create it
    report_file_path = os.path.join(usb_directory, 'compression_report.txt')
    if not os.path.exists(report_file_path):
        with open(report_file_path, 'w') as report_file:
            report_file.write("Compression Report:\n")

    # For calculating time elapsed during encryption
    start_time = time.time()

    for file_name, _ in selected_files:
        # Get the full path of the file
        file_path = os.path.join(usb_directory, file_name)

        # Default to chacha20 if the algorithm is not specified or unsupported
        if algorithm not in ['AES', 'CHACHA20']:
            print(f"\nUnsupported or unspecified encryption algorithm: '{algorithm}'. Defaulting to ChaCha20.")
            algorithm = 'CHACHA20'

        # Generate a random nonce based on the encryption algorithm
        nonce_length = 8 if algorithm == 'CHACHA20' else 16
        nonce = get_random_bytes(nonce_length)

        # Read the plaintext from the file
        with open(file_path, 'rb') as infile:
            plaintext = infile.read()

        # Initialise the ciphertext variable
        ciphertext = None

        # Compress the plaintext based on the compression option
        if compression_option == 1:  # Lossless Compression
            plaintext = lossless_compress(plaintext)
        elif compression_option == 2:  # Lossy Compression
            plaintext = lossy_compress(plaintext, file_name)

        # Update the new total size after compression
        new_total_size += len(plaintext) / (1024 ** 2)

        # Encrypt the compressed plaintext
        if algorithm == 'CHACHA20':
            # Create a ChaCha20 cipher with the key and nonce
            cipher = ChaCha20.new(key=key, nonce=nonce)
            # Encrypt the plaintext
            ciphertext = cipher.encrypt(plaintext)

        elif algorithm == 'AES':
            # Pad the plaintext before encryption
            padded_plaintext = pad(plaintext, AES.block_size)
            # Create an AES cipher with the key and nonce
            cipher = AES.new(key, AES.MODE_CBC, nonce)
            # Encrypt the padded plaintext
            ciphertext = cipher.encrypt(padded_plaintext)

        # Write the nonce and ciphertext to a new file
        encrypted_file_path = os.path.join(usb_directory, f'encrypted_{file_name}')
        with open(encrypted_file_path, 'wb') as outfile:
            outfile.write(nonce)
            outfile.write(ciphertext)

        print(f"File '{file_name}' encrypted.")

        # Create a backup of the unencrypted file in the backup directory
        shutil.copy(file_path, os.path.join(backup_directory, file_name))

        # Delete the original file after encryption
        os.remove(file_path)

    # Store the encryption key, algorithm and compression option in user_data
    if current_user:
        user_data[current_user]['user_key'] = key
        user_data[current_user]['encryption_algorithm'] = algorithm
        user_data[current_user]['compression_option'] = compression_option
        # Save user data to a file immediately after encrypting files
        with open(user_data_file, 'w') as file:
            file.write(str(user_data))

    # Display the new total size after compression
    print(f"\nTotal size of encrypted files: {new_total_size:.2f} MB")

    print("\nEncryption complete. Backup folder updated.")

    # Display total time taken to complete process
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Time Elapsed: {elapsed_time:.2f} seconds")

    return backup_directory

def decrypt_files(selected_files, backup_directory):
    global current_user

    # Retrieve the user's encryption key, algorithm and compression method from user_data
    user_key = user_data[current_user].get('user_key')
    algorithm = user_data[current_user].get('encryption_algorithm')
    compression_option = user_data[current_user].get('compression_option', 3)
    if not user_key or not algorithm or not compression_option:
        print("\nEncryption key, algorithm and/or compression method not found. Cannot decrypt files.")
        return

    # Keep track of decrypted files so they don't get decrypted again
    decrypted_files = []

    # For calculating time elapsed during decryption
    start_time = time.time()

    for file_name, _ in selected_files:
        # Check if the file has already been decrypted
        if file_name in decrypted_files:
            print(f"File '{file_name}' has already been decrypted. Skipping.")
            continue

        # Get the full path of the encrypted file
        encrypted_file_path = os.path.join(usb_directory, f'encrypted_{file_name}')

        # Check if the encrypted file exists
        if not os.path.exists(encrypted_file_path):
            continue

        # Read the nonce and ciphertext from the encrypted file
        with open(encrypted_file_path, 'rb') as infile:
            nonce_length = 8 if algorithm == 'CHACHA20' else 16
            nonce = infile.read(nonce_length)
            ciphertext = infile.read()

        # Decrypt the ciphertext
        if algorithm == 'CHACHA20':
            # Create a ChaCha20 cipher with the key and nonce
            cipher = ChaCha20.new(key=user_key, nonce=nonce)
            # Decrypt the ciphertext
            plaintext = cipher.decrypt(ciphertext)

        elif algorithm == 'AES':
            # Create an AES cipher with the key and nonce
            cipher = AES.new(user_key, AES.MODE_CBC, nonce)
            # Decrypt the ciphertext
            plaintext = cipher.decrypt(ciphertext)

            # Unpad the decrypted plaintext
            plaintext = unpad(plaintext, AES.block_size)

        # Decompress the plaintext based on the compression option
        if compression_option == 1:  # Lossless Compression
            plaintext = lossless_decompress(plaintext)
        elif compression_option == 2:  # Lossy Compression
            plaintext = lossy_decompress(plaintext)

        # Write the decrypted plaintext to a new file
        decrypted_file_path = os.path.join(usb_directory, file_name)
        with open(decrypted_file_path, 'wb') as outfile:
            outfile.write(plaintext)

        decrypted_files.append(file_name)
        print(f"File '{file_name}' decrypted.")

    print("\nDecryption complete.")
    
    # Display total time taken to complete process
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Time Elapsed: {elapsed_time:.2f} seconds")

    # Delete the original encrypted files
    delete_original_encrypted_files(selected_files)
    delete_backup_folder(backup_directory)

def delete_backup_folder(backup_directory):
    if os.path.exists(backup_directory):
        # Prompt the user before deleting the backup folder
        confirmation = input(f"\nDo you want to delete the backup folder '{backup_directory}'? (yes/no): ").lower()

        if confirmation == 'yes':
            # Delete the backup folder
            shutil.rmtree(backup_directory)
            print("\nBackup folder deleted.")
        else:
            print("\nBackup folder not deleted.")
    else:
        print("\nBackup folder not found. Nothing to delete.")

# Required for when a user encrypts files, leaves the program, and starts it again
def initialise_program():
    global image_files, backup_directory

    # List all files in the directory
    files = os.listdir(usb_directory)

    # Filter files that start with "encrypted_"
    encrypted_files = [file for file in files if file.startswith('encrypted_')]

    # Populate image_files with encrypted files
    image_files = [(file[len('encrypted_'):], 'dummy_image_type') for file in encrypted_files]

    # Check if a backup folder exists, otherwise create one
    backup_directory = os.path.join(usb_directory, 'backup')
    if not os.path.exists(backup_directory):
        os.makedirs(backup_directory)
        print(f"\nBackup folder '{backup_directory}' created.")

display_banner()

# Load user data from file
user_data_file = 'user_data.txt'
if os.path.exists(user_data_file):
    with open(user_data_file, 'r') as file:
        user_data = eval(file.read())

# Load USB directory from a text file
usb_directory_file = 'usb_directory.txt'
if os.path.exists(usb_directory_file):
    with open(usb_directory_file, 'r') as file:
        usb_directory = file.read().strip()

# If no text file found, ask for the path and add it to a new file
else:
    usb_directory = input("\nEnter the path to the USB drive: ")
    with open(usb_directory_file, 'w') as file:
        file.write(usb_directory)

initialise_program()

while True:
    display_login_status()
    display_menu()

    choice = input("\nEnter your choice (1-4): ").strip()

    # Menu when a user is logged in
    if current_user:
        if choice == '1':
            current_user = None
            print("\nYou have been signed out.")

        elif choice == '2':
            image_files = list_image_files(usb_directory)

            if image_files:
                print(f"\nImages found in directory {usb_directory}:")
                for file_name, image_type in image_files:
                    print(f"{file_name}: {image_type}")

                # Warn the user about possible data loss
                print("\nWarning: Encryption will overwrite the original files.")
                confirmation = input("Are you sure you want to proceed? (yes/no): ").lower()
                
                if confirmation == 'yes':
                    # Prompt the user to select files for encryption
                    user_input = input("\nEnter file names to encrypt (comma-separated) or '*' to encrypt all: ")

                    if user_input == '*':
                        # Encrypt all files
                        key = get_random_bytes(32)
                        # Prompt the user to choose the encryption algorithm
                        print("\nEncryption Algorithms:")
                        print("1. ChaCha20")
                        print("2. AES")
                        algorithm_choice = input("Please select your encryption choice (1-2): ").strip()

                        # Check user input and set the algorithm accordingly
                        if algorithm_choice == '2':
                            algorithm_choice = 'AES'
                        elif algorithm_choice == '1':
                            algorithm_choice = 'CHACHA20'
                        else:
                            print("\nInvalid choice. Defaulting to ChaCha20.")
                            algorithm_choice = 'CHACHA20'

                        backup_directory = encrypt_files(image_files, key, algorithm_choice)
                    else:
                        # Encrypt selected files
                        selected_files = []
                        user_input_files = [file.strip() for file in user_input.split(',')]

                        for file_name in user_input_files:
                            # Check if the file exists
                            if os.path.exists(os.path.join(usb_directory, file_name)):
                                selected_files.append((file_name, 'dummy_image_type'))
                            else:
                                print(f"Warning: File '{file_name}' does not exist and will be skipped.")

                        # Check if no files have been selected
                        if not selected_files:
                            print("\nNo images selected, please choose at least 1 image for encryption.")
                        else:
                            key = get_random_bytes(32)
                            # Prompt the user to choose the encryption algorithm
                            print("\nEncryption Algorithms:")
                            print("1. ChaCha20")
                            print("2. AES")
                            algorithm_choice = input("Please select your encryption choice (1-2): ").strip()

                            # Check user input and set the algorithm accordingly
                            if algorithm_choice == '2':
                                algorithm_choice = 'AES'
                            elif algorithm_choice == '1':
                                algorithm_choice = 'CHACHA20'
                            else:
                                print("\nInvalid choice. Defaulting to ChaCha20.")
                                algorithm_choice = 'CHACHA20'

                            backup_directory = encrypt_files(selected_files, key, algorithm_choice)
                else:
                    print("\nEncryption aborted.")
            else:
                print("\nNo image files found in the directory.")

        elif choice == '3':
            # Check if any encrypted files exist
            encrypted_files = [file for file in os.listdir(usb_directory) if file.startswith('encrypted_')]
            if not encrypted_files:
                    print("\nNo encrypted files found. Nothing to decrypt.")
            else:
                # Print the list of encrypted files
                print("\nEncrypted files found in directory:")
                for encrypted_file in encrypted_files:
                    print(encrypted_file)

                # Prompt the user to select files for decryption
                user_input_decrypt = input("\nEnter file names to decrypt (comma-separated and ignoring the encrypted_ prefix) or '*' to decrypt all: ")
                if user_input_decrypt == '*':
                    # Decrypt all files
                    decrypt_files([(f, 'dummy_image_type') for f, _ in image_files], backup_directory)
                else:
                    # Decrypt selected files
                    selected_files_decrypt = [(file.strip(), 'dummy_image_type') for file in user_input_decrypt.split(',')]
                    decrypt_files(selected_files_decrypt, backup_directory)

        elif choice == '4':
            # Save user data to a file before exiting
            with open(user_data_file, 'w') as file:
                file.write(str(user_data))
            print(f"\nThank you for using Exodus USB Encryption, {current_user}.")
            break
        else:
            print("\nInvalid choice. Please enter a number 1-4")

    # Menu when no user logged in       
    else:
        if choice == '1':
            login()
        elif choice == '2':
            signup()
        elif choice == '3':
            print("\nInvalid option.")
        elif choice == '4':
            # Save user data to a file before exiting
            with open(user_data_file, 'w') as file:
                file.write(str(user_data))
            print("\nThank you for using Exodus USB Encryption.")
            break  # Exit the loop
        else:
            print("\nInvalid choice. Please enter a number 1-4")