from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
import os
import os.path
import sys
import subprocess
import multiprocessing

from scripts.key_generator import read_keys, generate_aes_key, save_encryption_config, generate_rsa_keypair, load_aes_key, generate_iv
from scripts.encryption import encrypt, decrypt, encrypt_aes

if sys.platform == "win32":
    FILEBROWSER_PATH = "explorer"
elif sys.platform == "darwin":
    FILEBROWSER_PATH = "open"
else:
    FILEBROWSER_PATH = "xdg-open"
    
folder_selected = 'FOLDER PATH'
processes = []
processCount = 10

def allfiles():
    allFiles = []
    if folder_selected != 'FOLDER PATH':
        for root, subfiles, files in os.walk(folder_selected):
            for names in files:
                if not names == "crypt.py":
                    allFiles.append(os.path.join(root, names))

    global selected_files
    selected_files = allFiles
    return allFiles

def browseFolder():
    global folder_selected
    folder_selected = filedialog.askdirectory()
    if folder_selected == '':
        folder_selected = 'FOLDER PATH'
        resetAll()
    else:
        path["text"] = folder_selected
        listbox.delete(0,END)
        for f, file in enumerate(allfiles()):
            listbox.insert(f, file)
        path.grid(row=0, column=0, columnspan=3)
        listbox.grid(row=2, column=0, columnspan=3)
        resetBtn.grid(row=4, column=0, columnspan=3)
        openFolderBtn.grid(row=3, column=0, columnspan=3)
        
def openFolder():
    folderPath = os.path.normpath(folder_selected)

    if os.path.isdir(folderPath):
        subprocess.run([FILEBROWSER_PATH, folderPath])
    elif os.path.isfile(folderPath):
        subprocess.run([FILEBROWSER_PATH, '/select,', folderPath])
        
def encryptFiles(filesList):
    for fileName in filesList:
        if '.knight' not in fileName:
            with open(fileName, 'rb') as fo:
                plaintext = fo.read()
            aes_key = load_aes_key()
            public_key, private_key = read_keys()
            iv = generate_iv()
            encrypted_data = encrypt(plaintext, public_key, aes_key, iv)
            with open(fileName + ".knight", 'wb') as fo:
                fo.write(iv)  # Write the IV first
                fo.write(encrypted_data[2])  # Then write the encrypted data
            os.remove(fileName)
                
def decryptFiles(filesList):
    for fileName in filesList:
        if '.knight' in fileName:
            with open(fileName, 'rb') as fo:
                plaintext = fo.read()
            aes_key = load_aes_key()
            public_key, private_key = read_keys()
            
            iv = plaintext[:16]
            plaintext = plaintext[16:]
            
            encrypt_aes_key, encryptor = encrypt_aes(public_key, aes_key, iv)
            
            decrypted_data = decrypt(plaintext, private_key, encrypt_aes_key, iv)
            output_filename = fileName[:-7] if fileName.endswith('.knight') else fileName + '_decrypted'
            with open(output_filename, 'wb') as fo:
                fo.write(decrypted_data)
            os.remove(fileName)
        
def encryptProcess():
    if folder_selected == 'FOLDER PATH' or folder_selected == '':
        messagebox.showerror("Unable to encrypt", "Please select a folder!")
    else:
        allFiles = list(filter(lambda encFile: encFile.split("\\")[len(encFile.split("\\")) - 1] != os.path.basename(sys.executable), allfiles()))
        encFilesList = [allFiles[x:x+processCount] for x in range(0, len(allFiles), processCount)]
        global processes
        for fileList in encFilesList:
            p = multiprocessing.Process(name="encrypt", target=encryptFiles, args=(fileList,))
            p.start()
            processes.append(p)

        for process in processes:
            process.join()
        resetListBox()
        messagebox.showinfo("showinfo", "Encryption Done!")
    
def decryptProcess():
    if folder_selected == 'FOLDER PATH' or folder_selected == '':
        messagebox.showerror("Unable to decrypt", "Please select a folder!")
    else:
        allFiles = list(filter(lambda encFile: encFile.split("\\")[len(encFile.split("\\")) - 1] != os.path.basename(sys.executable), allfiles()))
        encFilesList = [allFiles[x:x+processCount] for x in range(0, len(allFiles), processCount)]
        global processes
        for fileList in encFilesList:
            p = multiprocessing.Process(name="decrypt", target=decryptFiles, args=(fileList,))
            p.start()
            processes.append(p)

        for process in processes:
            process.join()
        resetListBox()
        messagebox.showinfo("showinfo", "Decryption Done!")
    
def resetListBox():
    listbox.delete(0,END)
    for f, file in enumerate(allfiles()):
        listbox.insert(f, file)
        
def resetAll():
    global folder_selected
    folder_selected = 'FOLDER PATH'
    path["text"] = folder_selected
    listbox.delete(0,END)
    listbox.grid_forget()
    path.grid_forget()
    resetBtn.grid_forget()
    openFolderBtn.grid_forget()

def main():
    root.title("Encrypt/Decrypt")
    root.resizable(False, False)
    root.eval('tk::PlaceWindow . center')

    global path, listbox, resetBtn, openFolderBtn

    #Buttons
    path = Label(root, text='FOLDER PATH', pady=5, width=54 )
    browse = Button(root, text="Browse", padx=40, pady=5, command=lambda: browseFolder())
    enc = Button(root, text="Encrypt", padx=40, pady=5, command=lambda: encryptProcess())
    dec = Button(root, text="Decrypt", padx=40, pady=5, command=lambda: decryptProcess())
    listbox = Listbox(root, width=65, height=5)
    resetBtn = Button(root, text="Reset", padx=40, pady=5, command=lambda: resetAll(), width=43)
    openFolderBtn = Button(root, text="Open Folder", padx=40, pady=5, command=lambda: openFolder(), width=43)

    #Positioning
    browse.grid(row=1, column=0)
    enc.grid(row=1, column=1)
    dec.grid(row=1, column=2)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    
    if not os.path.exists('public_key.pem') and not os.path.exists('private_key.pem'):
        generate_rsa_keypair()
        
    if not os.path.exists('encryption_config.json'):
        aes_key = generate_aes_key()
        public_key, private_key = read_keys()
        encrypted_aes, iv, ciphertext = encrypt("", public_key, aes_key, generate_iv())
        save_encryption_config(aes_key)
        print("Encryption configuration saved to encryption_config.json")
    
    root = Tk()
    main()
    root.mainloop()