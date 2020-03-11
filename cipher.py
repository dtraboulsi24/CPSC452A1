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
        for i in range(rows):
            for j in range(cols):
                if counter >= len(text):
                    break
                cipherArray[i][j] = text[counter]
                counter += 1
        
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
    # To run this example: py cipher.py RTS 3421567 dec output.txt input.txt
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

    def decrypt(self, cipher):
        pass

class VIG(CipherInterface):
    pass

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
