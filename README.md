# aes-encryption-decryption

Overview:
       This program is an AES encryption and decryption program. It encrypts and decrypts in ECB and CBC modes.
 
  How To Run:
     Run java AES.java in the terminal
       Follow intructions to choose whether to encrypt or decrypt, decide mode, and entering filename and key filename
  
  Providing Input:
       FILES:
           Provide the file names for the files you want to encrypt or decrypt. You do not need to add quotation marks or any other 
           additional characters. Include the file name extension and make sure the file in the same directory that this program is in.
  
           Example from program:
               Enter filename: aes-plaintext1.txt
               Enter key filename: aes-key1.txt
      MODES:
           The program asks in the terminal what mode you want to use. Type the number corresponding to the mode that you want to use.
           
           Example from program:
               What mode? Enter the number corresponding to your choice.
               0: ECB
               1: CBC
               1
           
           In the example, the user inputted 1, so the program will use CBC.
  
  Notes:
       Make sure the filenames are exact as there is no file handling for incorrect filenames
       For "Enter filename", enter the file name for the ciphertext or the plaintext
       For "Enter key filename", enter the file name for the key
       Make sure to include the correct key file for the plaintext or ciphertext file
 
