#!/usr/bin/env python
# coding: utf-8

# # CSC-30012 - Workshop 4 
# ## Cryptography - Breaking the One-time Pad
# 
# This exercise aims at getting a practical understanding of the principles behind (symmetric) cryptography by attempting to break one of the simplest cyphers: the one-time pad.
# 
# Note that it is theoretically impossible to break this cypher, as it can be proven that it does achieve perfect secrecy. However, recall that the effectiveness of the cypher relies entirely on the fact that the key is used only once. When the key is shorter than the plain text, it will necessarily be used more than once, thus weakening the cypher.
# 
# We’ll simulate a scenario where you are an intruder who has been able to intercept the following message from an encrypted channel that used the one-time pad as encryption method:
# 
# ```EQYMRwIPKRdJEx8UKRdJFAgCMBwMRx4YNhoMCk0INk4GCQhBMQYIE00INk4ZCBoENwsNRwIHI0A=```
# 
# The only additional information you know about it is that it’s been encoded using base64, and that the length of the key used for one-time pad was 6.
# 
# Your job is to retrieve the original key and decrypt the message.
# 

# ## Useful functions
# Let's begin by defining some useful functions; you may want to keep those as reference.
# 
# You can execute the code in Python cells by selecting Cell > Run cells from the menu above (or the corresponding keyboard shortcut).

# In[ ]:


# Some imports and functions that will be useful in the following
import base64

# compute the XOR function of the byte representation of two strings
def byte_xor(ba1, ba2):
    """ XOR two byte strings """
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

# pretty-printing of a binary string as a sequence of bits
def byte_print(binstr):
    for byte in binstr:
        print(format(byte, '08b'), end=" ")
    print()
    
# pretty-printing of a binary string as a sequence of bits, in groups of 6 bits
def byte_print64(binstr):
    bits = ''.join(format(byte, '08b') for byte in binstr)
    bitstr = ' '.join([bits[i:i+6] for i in range(0, len(bits), 6)])
    # add padding
    extra = len(bits) % 6
    if extra > 0:
        bitstr = bitstr + ('0' * (6 - extra))
    print(bitstr)


# These are some additional utility functions, mainly of interest for this exercise only:

# In[ ]:


# printing a message with enough space for tabulation
def tabular_print(text, tab):
    print(format(text, '<'+str(tab)), end='')
    
# this will try to 
def trytext(ciphertext, partialkey, keylen):
    if (len(partialkey) > keylen):
        partialkey = partialkey[0:keylen]
    
    pad = (keylen-len(partialkey)) * b'*'

    decrypt = b''
    for i in range(0, len(ciphertext), keylen):
        chunk = ciphertext[i:i+len(partialkey)]
        decrypt += byte_xor(chunk, partialkey)
        decrypt += pad

    print(decrypt)


# ## Part I: Encoding - ASCII and base64
# 
# In order for the machine to process them, strings are represented internally as sequences of bits. 
# 
# ### ASCII
# In order to convert human-readable characters into bits you need a code and the most famous one is undoubtedly the **ASCII** code, which used 8 bits to represent each character. 
# 
# In Python, strings are simply created by eclosing characters into (single or double) quotes: ```str = 'foobar'```.
# 
# Prefixing a string literal with ```b``` produces an instance of the _bytes_ type instead of the _string_ type: ```str = b'foobar'``` which effectively corresponds to the representation of that string in 8-bit ASCII code.
# You can also obtain the same encoding by calling this method on the string: ```str.encode('ascii')```
# 
# ### base64
# Unfortunately, besides all the alphanumeric symbols, the ASCII code contains many control characters. If you were to interpret any sequence of bits transmitted across the network as an ASCII code, the binary sequence might inadvertently contain control codes that would muddle the transmission.
# 
# An alternative code (used for example in e-mail protocols) is **base64**, which splits the binary sequence in groups of **6 bits** that may always be represented using _printable_ characters. (The garbled sequence of characters that you see if you open an email with attachments with a text editor is exactly the base64 encoding of the attachment).
# 
# In Python, we can use the encoding/decoding methods provided by the ```base64``` package, as shown below.
# 
# We don't need to discuss the details of base64 encoding, but if you're interested you can find additional information [here](https://stackabuse.com/encoding-and-decoding-base64-strings-in-python/).
# 

# In[ ]:


text = 'Cat'

# Let's encode the string in base64
text_ascii = text.encode('ascii') # 3 chars are encoded with 3 bytes ( = 24 bits) in ASCII
text_base64 = base64.b64encode(text_ascii) # and 4 bytes (24/6 = 4) in base64

tabular_print('Python string:', 30)
print(text)

tabular_print('ASCII encoding:', 30)
byte_print(text_ascii)

tabular_print('base64 encoding:', 30)
print(text_base64)

tabular_print('base64 encoding (binary):', 30)
byte_print64(text_ascii)

text_base64_bytes = base64.decodebytes(text_base64)
tabular_print('base64 decoding:', 30)
print(text_base64_bytes)

tabular_print('base64 decoding (binary):', 30)
byte_print(text_base64_bytes)


# ## Part II: Working with XOR
# 
# The binary operator XOR ($\oplus$) is fundamental in cryptography.
# 
# Recall that the truth table for XOR is:
# 
# | a | b | a $\oplus$ b | 
# | :-: | :-: | :-: |
# | 0 | 0 | 0|
# | 0 | 1 | 1|
# | 1 | 0 | 1|
# | 1 | 1 | 0|
# 
# Basically: if two bits are the same, the result is 0; if they are different, it's 1.
# 
# Let's use it with strings (remember to use the binary version of the strings):

# In[ ]:


# Let's define two (binary) strings
text1 = b'test'
text2 = b'help'

tabular_print('Text1:', 20)
byte_print(text1)

tabular_print('Text2:', 20)
byte_print(text2)

# Let's compute the XOR; compare with the truth table above and make sure it makes sesne to you
tabular_print('Text1 xor Text2:', 20)
res = byte_xor(text1, text2)
byte_print(res)


# ## Part III: One-time pad
# 
# The _one-time pad_ (OTP) is one of the most famous techniques for symmetric cryptography. 
# 
# Given a _plaintext_ $p$ (an unencrypted string), the corresponding encryption is the _ciphertext_ obtained via a xor operation between the plaintext and a secret key $k$ (the one-time pad):
# 
# $e = p \oplus k$
# 
# 
# It can be proven that OTP can achieve **perfect secrecy** (i.e. it is unbreakable) if _all_ of the following conditions are met:
#  - the key must be truly random;
#  - the key must be **at least as long** as the plaintext;
#  - the key must **never be reused** in whole or in part;
#  - the key must be kept completely secret (that's the basic principle for symmetric cryptography).
# 
# If you consider two plaintexts enrypted with _the same_ pad $k$, you would have:
# 
# $e_1 = p_1 \oplus k$
# 
# $e_2 = p_2 \oplus k$
# 
# Due to the properties of XOR, you also have:
# 
# $e_1 \oplus p_1 = k$
# 
# $e_2 \oplus p_2 = k$
# 
# and
# 
# $e_1 \oplus e_2 = p_1 \oplus p_2$.
# 
# This implies that if you are able to find just one pair of plaintext/ciphertext you can decrypt all messages.

# ---
# ## Part IV: Cracking the code
# 
# You've been able to intercept the following message from an encrypted channel that used the one-time pad as encryption method:
# 
# ```EQYMRwIPKRdJEx8UKRdJFAgCMBwMRx4YNhoMCk0INk4GCQhBMQYIE00INk4ZCBoENwsNRwIHI0A=```
# 
# 
# The only additional information you know about it is that it's been encoded using base64, and that **the lenght of the key used for one-time pad was 6**.
# 
# Your job is to retrieve the original key, and decrypt the message.
# 
# <div align="center">***</div>
# 
# **Hints:**
# 
# - Remember you can decode from base64 by using the method: ```base64.b64decode()```
# - If ```str``` is a string, you can easily extract substrings in Python with the syntax: ```str[n1:n2]``` which will produce the substring starting in position ```n1``` up to position ```n2``` (not included).
# For instance if ```str = 'exercise'```, then ```str[0:3]``` is ```exe```
# - The one-time pad is not supposed ot be reused. If the key is used more than once, this means you can split the ciphertext in chunks of the size of the key and exploit them to break the code
#   - split the ciphertext using the string operators described above
#   - use XOR to see if decrypting it makes any sense (you can use the ```byte_xor()``` provided method
# - Once you think you have a good guess, you may try applying it to the entire message with the utility method:  
# ```trytext(ciphertext, guessed_key, keylen)```  
# whose arguments are: the original ciphertext, your guess for the key, and the known length for the key (6 in our example)

# ## Solution

# In[ ]:


# NOTE: this code won't run until you complete it

ciphertext_base64 = b'EQYMRwIPKRdJEx8UKRdJFAgCMBwMRx4YNhoMCk0INk4GCQhBMQYIE00INk4ZCBoENwsNRwIHI0A='

# Let's begin by decoding the ciphertext

##################
# YOUR CODE HERE #
ciphertext = base64.b64decode(ciphertext_base64)
##################


# Now we'll try to attack the cypher by guessing parts of the plaintext, making use of our previous knowledge.

# Let's assume the plaintext begins with "it":

# In[ ]:


# Try to guess parts of the plaintext (e.g. the first word: 'the' or 'it' or...)
guess = b'it '

# If your guess is correct, you might be able to retrieve part of the key
##################
# YOUR CODE HERE #
# compute XOR between the first chuck of length 6 of the ciphertext and your guessed key
guessed_key = byte_xor(guess, ciphertext[0:len(guess)])
##################

print('The key you guessed so far is: ', end ='')
print(guessed_key)


# Note that, assuming the first word is "it", we may as well try to guess an additional character, so I actually attempted with "it " (with a leading space).
# 
# Anyway, that doesn't look like a good guess for the key.
# Let's try again with some other common word that might start an English sentence, for example: "the":

# In[ ]:


# Try to guess parts of the plaintext (e.g. the first word: 'the' or 'it' or...)
guess = b'the'

# If your guess is correct, you might be able to retrieve part of the key
##################
# YOUR CODE HERE #
# compute XOR between the first chuck of length 6 of the ciphertext and your guessed key
guessed_key = byte_xor(guess, ciphertext[0:len(guess)])
##################

print('The key you guessed so far is: ', end ='')
print(guessed_key)


# That is not particularly enlightening, but it is at least a possible combination of letter in English.
# Any clue about a possible key?
# 
# Note that I forgot my consideration about the leading space... let's add it back:

# In[ ]:


# Try to guess parts of the plaintext (e.g. the first word: 'the' or 'it' or...)
guess = b'the '

# If your guess is correct, you might be able to retrieve part of the key
##################
# YOUR CODE HERE #
# compute XOR between the first chuck of length 6 of the ciphertext and your guessed key
guessed_key = byte_xor(guess, ciphertext[0:len(guess)])
##################

print('The key you guessed so far is: ', end ='')
print(guessed_key)


# Now that seems to be leading somewhere!
# 
# You might have guessed already, but in real-life cases we might not be so lucky. 
# Let's double check first if what we've got so far is promising...

# In[ ]:


print('The key you guessed so far is: ', end ='')
print(guessed_key)

# Since the key has been reused, try to see if this decrypts more than one part of your message
chunk1 = ciphertext[0:6]
decrypt1 = byte_xor(guessed_key, chunk1)
print('First chunk: ', end = '')
print(decrypt1)

##################
# YOUR CODE HERE #
# extract second chunk of 6 characters from ciphertext
chunk2 = ciphertext[6:12]
#
# compute XOR between the chuck and the guessed key
decrypt2 = byte_xor(guessed_key, chunk2)

print('Second chunk: ', end = '')
print(decrypt2)
##################


# Doesn't seem too clear. Let's look at decrypting the entire text with our temporary partial key:

# In[ ]:


##################
# YOUR CODE HERE #
trytext(ciphertext, guessed_key, 6)
##################


# Something looks out of place: capital letters in the middle of a sentence.
# 
# Maybe our key needs to be tweaked: "The " instead of "the ".
# 
# Let's try again:

# In[ ]:


# Try to guess parts of the plaintext (e.g. the first word: 'the' or 'it' or...)
guess = b'The '

# If your guess is correct, you might be able to retrieve part of the key
##################
# YOUR CODE HERE #
# compute XOR between the first chuck of length 6 of the ciphertext and your guessed key
guessed_key = byte_xor(guess, ciphertext[0:len(guess)])
##################

print('The key you guessed so far is: ', end ='')
print(guessed_key)

# Since the key has been reused, try to see if this decrypts more than one part of your message
chunk1 = ciphertext[0:6]
decrypt1 = byte_xor(guessed_key, chunk1)
print('First chunk: ', end = '')
print(decrypt1)

##################
# YOUR CODE HERE #
# extract second chunk of 6 characters from ciphertext
chunk2 = ciphertext[6:12]
#
# compute XOR between the chuck and the guessed key
decrypt2 = byte_xor(guessed_key, chunk2)

print('Second chunk: ', end = '')
print(decrypt2)
##################

##################
# YOUR CODE HERE #
trytext(ciphertext, guessed_key, 6)
##################


# At this point, we have cracked enough of the plaintext that we might start completing our guess for it and from there complete our guess of the key.
# 
# However, in our simple case it's clear that the key is in fact "Enigma".
# Let's just try it out:

# In[ ]:


guessed_key = b'Enigma'

##################
# YOUR CODE HERE #
trytext(ciphertext, guessed_key, 6)
##################


# And that gives us reasonable certainty that we've cracked the system!

# In[ ]:




