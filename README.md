e2ee-im-terminal-app
=========

this app's goal is to provide an instant messaging service that at no point, anyone other than the sender and recipients of messages have any ability to view contents of

Key points:
----------
* Uses a unique public private key pair for every device (counts the browser as one device)  
* Generates rsa key for browser based off seeding a prng with a hash generated from the user's salted password (salt stored on server, key generation done on device)  
* On password change, previous messages unable to be recovered unless using a previous device, or until a previous device has logged in with the new password  
* Password hashed on device before being hashed again at the server to compare hashes such that server never can log plain text password (as is used in rsa key gen)  

Database schema:
----
```
Users:
    UserID PK
    username
    hash
    client_salt
    server_salt
Devices:
    DeviceID PK
    UserID FK
    RSAKey
Conversations:
    ConversationID PK
    name
UserConversationMap:
    UserConversationMapID PK
    UserID FK
    ConversationID FK
Messages:
    MessageID PK
    SenderID FK
    ConversationID FK
    senttime
Digests:
    DigestID PK
    MessageID FK
    DeviceID FK
    contents
```
