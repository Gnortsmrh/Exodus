Welcome to Exodus USB Encryption, a Python program designed to encrypt and decrypt image files on a USB drive. 
This README will guide you through the usage of the program.

1. Installation:
   - Ensure you have Python 3 installed on your system.
   - Clone or download the source code from Blackboard
   - Extract the files to a directory of your choice.

2. Configuration:
   - Ensure the 'ascii_banner.txt' file is in the same directory as Exodus.py
   - 'user_data.txt' and 'usb_directory.txt' will be generated upon account creation, leave these files in the directory they appear in to avoid configuration settings and account loss.

3. Running the Program:
   - Open a terminal or command prompt and navigate to the directory where you extracted the source code.
   - Run the program by executing the following command:

     python Exodus.py

   - Alternatively, open the project folder within Visual Code and run the program as a Python File.
   - Follow the on-screen instructions to log in or sign up, encrypt files, decrypt files, or sign out.

4. Usage:
   - USB Directory: Follow the on-screen prompt and enter the path to your USB drive's images e.g. 'F:\Photos'.
   - Log In: If you have an existing account, enter your username and password to log in.
   - Sign Up: If you are a new user, create a new account by providing a username, password, and optionally enabling secure file deletion.
   - Encrypt Files: Select files from your USB drive to encrypt. You can choose to encrypt all files or specific ones. Choose the encryption algorithm (ChaCha20 or AES) and compression option (lossless, lossy, or none).
   - Decrypt Files: Select encrypted files to decrypt. You can choose to decrypt all files or specific ones. Avoid decrypting images in bulk when they were encrypted using varying algorithms.
   - Sign Out: Log out of your current session.

5. Important Notes:
   - Secure File Deletion: Enabling secure file deletion will permanently delete encrypted files after a specified number of failed login attempts.
   - Backup: Encrypted files will be backed up in a 'backup' folder within your USB directory before encryption. Successful decryption will prompt you to delete this folder but you are welcome to remove it whenever you wish.

6. Additional Information:
   - If you encounter any issues or have questions, please refer to this README or contact the program maintainer at harmstrong5@uclan.ac.uk.

Thank you for using Exodus USB Encryption!