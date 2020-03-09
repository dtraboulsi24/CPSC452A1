import sys

class CipherInterface:
    def __init__(self):
        self.key = None

    def setKey(self, key):
        self.key = key

class PLF(CipherInterface):
    pass

class RTS(CipherInterface):
    pass

class RFC(CipherInterface):
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
