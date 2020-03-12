import sys
import math

class CipherInterface:
    def __init__(self):
        self.key = None

    def setKey(self, key):
        self.keyLength = len(key)
        self.key = key

class PLF(CipherInterface):
    pass


class RTS(CipherInterface):
    def __init__(self):
        super(RTS, self).__init__()

    # Takes in plaintext and encrypts using Row Transposition Cipher with a key to read the rows
    # Returns ciphered text 
    # example input: attack postponed until two am
    # example key: 3421567
    # example output: TTNAAPTMTSUOAODWCOIZKNLZPETZ
    def encrypt(self, text):
        cipher = ''

        # clean up plaintext by removing spaces and ensuring uppercase
        text = text.replace(" ", "")
        text = text.upper()

        
        # number of rows is len of plaintext divided by len of key
        rows = int(math.ceil(len(text) / self.keyLength))

        # number of cols is key length
        cols = self.keyLength

        # init cipher array, put in Z's for extra space
        cipherArray = [['Z'] * cols for i in range(rows)]
        
        # overwrite array with the plaintext message
        # goes through columns first setting values vertically 
        counter  = 0
        i = 0
        while i < rows:
            for j in range(cols):
                if counter >= len(text):
                    break
                cipherArray[i][j] = text[counter]
                counter += 1
            i += 1
        
        # read columns from top to bottom to get ciphertext
        for i in range(self.keyLength):
            for j in range(rows):
                cipher += cipherArray[j][int(self.key[i]) - 1]
        return cipher

    # Takes in ciphered text and decrypts using Row Transposition Cipher with a key to read the rows
    # Returns plaintext 
    # example input: TTNAAPTMTSUOAODWCOIZKNLZPETZ
    # example key: 3421567
    # example output: ATTACKPOSTPONEDUNTILTWOAMZZZ
    def decrypt(self, cipher):
        text = ''

        # clean up spaces and uppercase, just in case
        cipher = cipher.replace(" ", "")
        cipher = cipher.upper()

        # number of rows is len of plaintext divided by len of key
        rows = int(math.ceil(len(cipher) / self.keyLength))

        # number of cols is key length
        cols = self.keyLength

        # init cipher array, put in Z's for extra space
        cipherArray = [['Z'] * cols for i in range(rows)]

        # overwrite array with ciphertext, invert rows and cols order compared to encrypt
        # goes through rows first setting the values horizontally
        counter = 0
        for i in range(cols):
            for j in range(rows):
                cipherArray[j][i] = cipher[counter]
                counter += 1

        # construct the plaintext by accessing the row sequentially, and the col via the key
        for i in range(rows):
            for j in range(cols):
                # get current column by finding the indicy in the key
                currentCol = self.key.find(str(j+1))
                text += cipherArray[i][currentCol]
        return text


class RFC(CipherInterface):
    def __init__(self):
        super(RFC, self).__init__()
    

    # Encrypt using Railfence cipher. Take in plaintext message and a "Rail" key size
    # iterate through message, building cipher according to key size
    # return ciphertext
    # example input: this is a test
    # example key: 3
    # example output: TSASHITTISE
    def encrypt(self, text):
        cipher = ''
        
        # clean up plaintext by removing spaces and ensuring uppercase
        text = text.replace(" ", "").upper()
        # set rows to be key size
        rows = int(self.key)
        # set cols to be plaintext size / key size rounded up
        cols = math.ceil(len(text)/int(self.key))
        #  set blank railArray
        railArray = [[' '] * cols for i in range(rows)]
        # print(railArray)

        #  loop through rows first then cols, assigning chars from the message into the rail array 
        row, col = 0, 0
        # loop through the message, setting the chars in the railArray across rows then columns
        for i in range(len(text)):
            railArray[row][col] = text[i]
            if row != int(self.key) - 1: 
                row += 1
            else:
                row = 0
                col += 1
        # print("Rail Array: ", railArray)

        # read the railArray into a string to become the ciphertext
        for i in range(rows):
            for j in range(cols):
                if railArray != '\n':
                    cipher += railArray[i][j]
                
        # print(cipher)
        # clean up spaces 
        cipher = cipher.replace(" ", "")
        return cipher

    # Takes in a ciphertext and constructs the plaintext using Railfence Cipher decryption
    # example input: TSASHITTISE
    # example key: 3
    # example output: THISISATEST 
    # returns plaintext
    def decrypt(self, cipher):
        text = ''
 
        # clean up ciphertext by removing spaces and ensuring uppercase
        cipher = cipher.replace(" ", "").upper()
 
        # set rows to be key size
        rows = int(self.key)
        # set cols to be ciphertext size / key size rounded down
        cols = math.floor(len(cipher)/int(self.key))
 
        # now find partially filled cols and how many letters are left in them
        leftover = len(cipher) % int(self.key)
        # print("leftover: ", leftover)
        # set blank railArray, taking into account leftover letters
        if leftover != 0:
            cols += int(self.key) % leftover
        railArray = [[' '] * cols for i in range(rows)]
        # print(railArray)
        
        # loop through cols first then rows, assigning chars from the message into the rail array 
        row, col = 0, 0
        # loop through the cipher, setting the chars in the railArray across rows then columns
        for i in range(len(cipher)):
            railArray[row][col] = cipher[i]
            if leftover != 0 and col != int(self.key): 
                # print("col before ", col)
                col += 1
                # print("col after ", col)
            elif leftover == 0 and col != (int(self.key) - 1):
                 col += 1
            else:
                col = 0
                row += 1
        # print(railArray)
 
        # construct the plaintext by reading rows first then cols
        for i in range(cols):
           for j in range(rows):
                if railArray != '\n':
                    text += railArray[j][i]
        # print(text)
        return text


class VIG(CipherInterface):
    def __init__(self):
        super(VIG, self).__init__()
 
    # encrypt a plaintext message using the Vigenre's cipher. The key is constructed 
    # by duplicating itself until the massage length is met. 
    # Then the ascii of the key and message char's are added and modulo by 26 and converted to uppercase.
    # This result is then appended to the ciphertext
    # example input: hello world
    # example key: WILL
    # example output: DMWWKEZCHL
    def encrypt(self, text):
        cipher = ''
 
        # clean up plaintext
        text = text.replace(" ", "")
        text = text.upper()
        
        # clean up key
        self.key = self.key.replace(" ", "")
        self.key = self.key.upper()
 
        # print("key before: ", self.key)
        # print("Key length: ", self.keyLength)
        # print("text length: ", len(text))
 
        # construct normal, repeating key
        # loop until key length matches plaintext length
        # constructing key from itself, and resetting index
        # when the index is at the end of the key
        i = 0
        while(self.keyLength < len(text)):
            if (i == self.keyLength):
                i = 0
            self.key += self.key[i]
            self.keyLength = len(self.key)
            i += 1
 
        # print("key after: ", self.key)
        # print("Key length: ", self.keyLength)    
 
        # go through text and encrypt using ascii values for letters
        # add the value of the plaintext and the key then mod 26 for alphabet, add 65 to ensure uppercase
        for i in range(len(text)):
            cipherChar = (ord(text[i]) + ord(self.key[i])) % 26 + 65
            cipher += chr(cipherChar)
        # print(cipher)
 
        return cipher
 
    # decrypt a ciphertext message using the Vigenre's cipher. The key is constructed 
    # by duplicating itself until the massage length is met. 
    # Then the ascii of the key and message char's are subtracted and modulo by 26 and converted to uppercase.
    # This result is then appended to the plaintext
    # example input: DMWWKEZCHL
    # example key: WILL
    # example output: HELLOWORLD
    def decrypt(self, cipher):
        text = ''
 
        # clean up key
        self.key = self.key.replace(" ", "")
        self.key = self.key.upper()
 
        # print("key before: ", self.key)
        # print("Key length: ", self.keyLength)
        # print("text length: ", len(text))
 
        # construct normal, repeating key
        # loop until key length matches plaintext length
        # constructing key from itself, and resetting index
        # when the index is at the end of the key
        i = 0
        while(self.keyLength < len(cipher)):
            if (i == self.keyLength):
                i = 0
            self.key += self.key[i]
            self.keyLength = len(self.key)
            i += 1
 
        # go through cipher and decrypt using ascii values for letters
        # subtract the value of the ciphertext and the key then mod 26 for alphabet, add 65 to ensure uppercase
        for i in range(len(cipher)):
            plainChar = (ord(cipher[i]) - ord(self.key[i])) % 26 + 65
            text += chr(plainChar)
        # print(text)
        return text

class CES(CipherInterface):
    def __init__(self):
        super(CES, self).__init__()

    def encrypt(self, text):
        cipher = ''
        shift = int(self.key)
        for char in text: 
            if char == ' ':
                cipher = cipher + char
            elif  char.isupper():
                cipher = cipher + chr((ord(char) + shift - 65) % 26 + 65)
            else:
                cipher = cipher + chr((ord(char) + shift - 97) % 26 + 97)
        return cipher

    def decrypt(self, text):
        cipher = ''
        shift = int(self.key)
        for char in text: 
            if char == ' ':
                cipher = cipher + char
            elif  char.isupper():
                cipher = cipher + chr((ord(char) - shift - 65) % 26 + 65)
            else:
                cipher = cipher + chr((ord(char) - shift - 97) % 26 + 97)
        return cipher

class HIL(CipherInterface):
    pass

class TRE(CipherInterface):
    pass

def fileRead(inputFile):
    file = open(inputFile, "r")
    return file.read()

def fileWrite(outputFile, text):
    file = open(outputFile, "w")
    file.write(text)

def main():
    cipher = None
    cipherName = sys.argv[1]
    enc = sys.argv[3]
    inputFile = sys.argv[4]
    outputFile = sys.argv[5]
    
    if cipherName == "PLF":
        cipher = PLF() 
    elif cipherName == "RTS":
        cipher = RTS()
    elif cipherName == "RFC":
        cipher = RFC() 
    elif cipherName == "VIG":
        cipher = VIG()
    elif cipherName == "CES":
        cipher = CES()
    elif cipherName == "HIL":
        cipher = CES() 
    elif cipherName == "TRE":
        cipher = CES()
    else:
        print("Enter supported cipher")
        exit

    cipher.setKey(sys.argv[2])
    text = fileRead(inputFile)

    if enc == "enc":
        text = cipher.encrypt(text)
    elif enc == "dec":
        text = cipher.decrypt(text)
    else:
        print("Choose enc/dec")
        exit
    
    fileWrite(outputFile, text)


if __name__ == "__main__":
    if len(sys.argv) == 6:
        main()
    else:
        print("Argument List Length Error")
