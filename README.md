# Bank-ATM Connection 

### In this project, you will implement an iterative secure banking system consisting of a bank server and multiple clients (i.e., the ATMs). Each bank user can use the ATM to transfer money to other users and view their account balance. The bank server manages a file “password” that stores user IDs and associated passwords, as shown below. In this project, you can create the file “password” manually.

#### chris 1234
### fey 5678
#### joe 9012

### The bank server also manages a file “balance” that keeps track of the savings and checking account balances for each user. The file “balance” has the following format:

<user-id> <saving-balance> <checking-balance>

### Here, <user-id> is the ID of the user. <saving-balance> and <checking-balance> represent the balances in the user’s savings and checking accounts, respectively. Initially, the file “balance” contains the following data, indicating $10,000 in the savings account and $1,000 in the checking account for each user.

####  chris 10000 1000
#### fey 10000 1000
#### joe 10000 1000

### Both public-key encryption and symmetric-key encryption methods are used for security. Let Kpub and Kprb denote the public and private key of the bank server, respectively. Assume that all clients (i.e., ATMs) have the bank’s public key. The public and private keys can be manually generated and stored on the disk. 

## The client is invoked as:
### atm <Bank server’s domain name> <Bank server’s port number> 
## The bank server is invoked as:
### bank <Bank server’s port number>

### The detailed steps are given below:
S1: The ATM establishes a connection with the bank server.
S2: The ATM prompts the user to enter their ID and password.
S3: The ATM generates a symmetric key K, sends E(Kpub, K) and E(K, ID||password) to the bank server, 
where ID and password are the user’s ID and password entered, respectively.
S4: The bank decrypts the E(Kpub, K) using Kprb to obtain the symmetric key K. The bank then decrypts 
E(K, ID||password) using K and obtains the user’s ID and the password. Next, the bank compares the ID 
and the password against the one stored in file “password”. If both the ID and the password are correct, 
then the server sends “ID and password are correct” to the ATM; otherwise, the server sends “ID or 
password is incorrect” to the ATM. The ATM then displays the message received from the server to the 
user.
S5: If the ID or the password is incorrect, the ATM prompts the user to re-enter the ID and password. 
Otherwise, the ATM displays the following main menu:
 Please select one of the following actions (enter 1, 2, or 3):
1. Transfer money
2. Check account balance
3. Exit
S6: If the user selects option 1, then they are prompted to select between transferring money from the 
savings account or the checking account:
 Please select an account (enter 1 or 2):
1. Savings
2. Checking
If the user enters an input other than 1 and 2, the ATM displays “incorrect input” and asks the user to select 
either the savings or checking account again. Otherwise, the ATM prompts the user to provide the 
recipient’s ID and the amount to be transferred. You can assume that the recipient’s ID will be different 
from the sender’s ID. You can also assume that the money will be transferred from the sender’s savings 
account to the recipient’s savings account or from the sender’s checking account to the recipient’s checking 
account.
Next, the ATM sends the account (1/2), the recipient’s ID, and the transfer amount to the server. The server 
checks if the recipient’s ID exist. If not, the server sends the message “the recipient’s ID does not exist” to 
the ATM. Otherwise, if the user’s account has sufficient funds, then the server updates the “balance” file, 
and sends “your transaction is successful” to the ATM. If there are insufficient funds, the server sends 
“Your account does not have enough funds” to the ATM. In the above cases, the ATM displays the 
message received from the server to the user and returns to the main menu.
S7. If the user selects the option 2, then the ATM sends “2” to the server. The server then responds by 
sending the balances of both the savings and checking accounts back to the ATM. Subsequently, the ATM
displays the balances in the following format:
 Your savings account balance: <amount>
 Your checking account balance: <amount>
The ATM then displays the main menu.
S8. If the user selects option 3, then the ATM sends “3” to the server, and both the ATM and the server 
close the connection socket, and the server continues listening for connection (i.e., the server should keep 
the listening socket open).
S9. If the user enters any input other than 1, 2, and 3, the ATM displays “incorrect input” and returns to the 
main menu












Name: Riddhi Patel
Email Address: rpate112@binghamton.edu
Programming Language: python3
Tested the code on remote.cs.binghamton.edu: YES
Execution Instructions:
1. The clinet is invoked as:
    -> atm <domain_name> <port_number>
2. The bank server is invoked as:
    -> bank <port_number> 
Code for Encryption/Decryption:
    -> Used RSA for Encrypting and Decrypting Symmertic Key.
    -> Used AES for Encrypting and Decrypting ID and password.
