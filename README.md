```
File Encryption Tool that allows users to secure their files using encryption and restore them using decryption. 

Encryption ensures that sensitive information remains protected by converting readable data into an unreadable format, 
while decryption allows authorized users to revert it back to its original state.

This project will introduce you to cryptographic concepts in Java using the built-in 
Java Cryptography Architecture (JCA). 

You will implement functionalities to:
Generate a 256-bit AES Secret Key for encryption and decryption process, and store it securely.
Encrypt a file, making its contents unreadable without the correct key.
Decrypt a file, restoring its original contents securely.


Accept user input to determine whether they want to generate a key, encrypt a file, decrypt a file, or exit the program.

1. If the user selects "Generate Key"
- A unique secret key is generated that we will use in Encryption and Decryption of a file.
- The key is stored securely in a file named `secret.key`.

2. If the user selects "Encrypt a File"
- Accept user input for the file to be encrypted (e.g., input.txt).
- Accept user input for the output file name where encrypted content will be stored (e.g., encrypt.txt).
- Encrypt the file using the previously generated key.

3. If the user selects "Decrypt a File"
- Accept user input for the file to be decrypted (e.g., encrypt.txt).
- Accept user input for the output file name where decrypted content will be stored (e.g., output.txt).
- Load the secret key and decrypt the file.

4. If the user selects "Exit"
- Display an exit message.
- Break out of the loop to terminate the program.
```