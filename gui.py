from tkinter import *
from tkinter.ttk import *
from tkinter import filedialog
from Crypto.Cipher import AES
from pathlib import Path

## -- Funciones Modos de Cifrado AES -- ##
def CifrarECB(llave, imagen):
  key = llave.encode()
  try:
    cipher = AES.new(key, AES.MODE_ECB)
  except:
      label2.config(text='Algo salió mal')

  with open(imagen, "rb") as f:
    imagen_name = Path(imagen).stem
    clear = f.read()
    a = len(clear)%16
    clear_trimmed = clear[64:-a]
    ciphertext = cipher.encrypt(clear_trimmed)
    ciphertext = clear[0:64] + ciphertext + clear[-a:]

  with open(f"./ImagenesCifradas/ECB/{imagen_name}_eECB.bmp", "wb") as f:
    f.write(ciphertext)

def CifrarCBC(llave, vector, imagen):
  iv = vector.encode()
  key = llave.encode()
  try:
      cipher = AES.new(key, AES.MODE_CBC, iv)
  except:
      label2.config(text='Algo salió mal')

  with open(imagen, "rb") as f:
    imagen_name = Path(imagen).stem
    clear = f.read()
    a = len(clear)%16
    clear_trimmed = clear[64:-a]
    ciphertext = cipher.encrypt(clear_trimmed)
    ciphertext = clear[0:64] + ciphertext + clear[-a:]

  with open(f"./ImagenesCifradas/CBC/{imagen_name}_eCBC.bmp", "wb") as f:
    f.write(ciphertext)

def CifrarCFB(llave, vector, imagen):
  iv = vector.encode()
  key = llave.encode()

  try:
      cipher = AES.new(key, AES.MODE_CFB, iv)
  except:
      label2.config(text='Algo salió mal')

  with open(imagen, "rb") as f:
    imagen_name = Path(imagen).stem
    clear = f.read()
    a = len(clear)%16
    clear_trimmed = clear[64:-a]
    ciphertext = cipher.encrypt(clear_trimmed)
    ciphertext = clear[0:64] + ciphertext + clear[-a:]

    with open(f"./ImagenesCifradas/CFB/{imagen_name}_eCFB.bmp", "wb") as f:
      f.write(ciphertext)

def CifrarOFB(llave, vector, imagen):
  iv = vector.encode()
  key = llave.encode()

  try:
    cipher = AES.new(key, AES.MODE_OFB, iv)
  except:
      label2.config(text='Algo salió mal')

  with open(imagen, "rb") as f:
    imagen_name = Path(imagen).stem
    clear = f.read()
    a = len(clear)%16
    clear_trimmed = clear[64:-a]
    ciphertext = cipher.encrypt(clear_trimmed)
    ciphertext = clear[0:64] + ciphertext + clear[-a:]

  with open(f"./ImagenesCifradas/OFB/{imagen_name}_eOFB.bmp", "wb") as f:
    f.write(ciphertext)

## -- Funciones Modos de Descifrado AES -- ##

def DecifrarECB(llave, imagen):
  key = llave.encode()

  try:
      cipher = AES.new(key, AES.MODE_ECB)
  except:
      label2.config(text='Algo salió mal')

  with open(imagen, "rb") as f:
    imagen_name = Path(imagen).stem
    clear = f.read()
    a = len(clear)%16
    clear_trimmed = clear[64:-a]
    ciphertext = cipher.decrypt(clear_trimmed)
    ciphertext = clear[0:64] + ciphertext + clear[-a:]

  with open(f"./ImagenesDescifradas/ECB/{imagen_name}_dECB.bmp", "wb") as f:
    f.write(ciphertext)

def DecifrarCBC(llave, vector, imagen):
  iv = vector.encode()
  key = llave.encode()

  try:
      cipher = AES.new(key, AES.MODE_CBC, iv)
  except:
      label2.config(text='Algo salió mal')

  with open(imagen, "rb") as f:
    imagen_name = Path(imagen).stem
    clear = f.read()
    a = len(clear)%16
    clear_trimmed = clear[64:-a]
    ciphertext = cipher.decrypt(clear_trimmed)
    ciphertext = clear[0:64] + ciphertext + clear[-a:]

  with open(f"./ImagenesDescifradas/CBC/{imagen_name}_dCBC.bmp", "wb") as f:
    f.write(ciphertext)

def DecifrarCFB(llave, vector, imagen):
  iv = vector.encode()
  key = llave.encode()
  try:
      cipher = AES.new(key, AES.MODE_CFB, iv)
  except:
      label2.config(text='Algo salió mal')

  with open(imagen, "rb") as f:
    imagen_name = Path(imagen).stem
    clear = f.read()
    a = len(clear)%16
    clear_trimmed = clear[64:-a]
    ciphertext = cipher.decrypt(clear_trimmed)
    ciphertext = clear[0:64] + ciphertext + clear[-a:]

  with open(f"./ImagenesDescifradas/CFB/{imagen_name}_dCFB.bmp", "wb") as f:
    f.write(ciphertext)

def DecifrarOFB(llave, vector, imagen):
  iv = vector.encode()
  key = llave.encode()

  try:
      cipher = AES.new(key, AES.MODE_OFB, iv)
  except:
      label2.config(text='Algo salió mal')

  with open(imagen, "rb") as f:
    imagen_name = Path(imagen).stem
    clear = f.read()
    a = len(clear)%16
    clear_trimmed = clear[64:-a]
    ciphertext = cipher.decrypt(clear_trimmed)
    ciphertext = clear[0:64] + ciphertext + clear[-a:]

  with open(f"./ImagenesDescifradas/OFB/{imagen_name}_dOFB.bmp", "wb") as f:
    f.write(ciphertext)

def DescifrarImagen():
    imagen = direccion.get()
    modo = clicked.get()
    llave = llaveVar.get()
    vector = vectorVar.get()

    if modo == "ECB":
        print("Descifrando en modo ECB")
        DecifrarECB(llave, imagen)
    elif modo == "CBC":
        print("Descifrando en modo CBC")
        DecifrarCBC(llave, vector, imagen)
    elif modo == "CFB":
        print("Descifrando en modo CFB")
        DecifrarCFB(llave, vector, imagen)
    elif modo == "OFB":
        print("Descifrando en modo OFB")
        DecifrarOFB(llave, vector, imagen)
    else:
        label2.config(text='Algo salió mal')

def CifrarImagen():
    imagen = direccion.get()
    modo = clicked.get()
    llave = llaveVar.get()
    vector = vectorVar.get()
    label2.config(text=f'Imagen cifrada con modo {modo}')

    if modo == "ECB":
        CifrarECB(llave, imagen)
    elif modo == "CBC":
        CifrarCBC(llave, vector, imagen)
    elif modo == "CFB":
        CifrarCFB(llave, vector, imagen)
    elif modo == "OFB":
        CifrarOFB(llave, vector, imagen)
    else:
        label2.config(text='Algo salió mal')

def mostrarModo():
    text_modos.config(text=f'Modo {clicked.get()} seleccionado')

def SubirImagen():
    global archivo
    archivo = filedialog.askopenfilename(title="Escoge un archivo", filetypes=[("BMP Files", "*.bmp")])
    direccion.set(archivo)

def mostrarProgreso():
    label2.config(text=f'Imagen cifrada con modo {clicked.get()}')

app = Tk()
app.title("Modos AES")
app.geometry("250x490")
app.configure(bg='black')
bgimg = PhotoImage(file="bg_img.ppm")
limb = Label(app, image=bgimg).place(x=0, y=0)
direccion = StringVar()
titulo = Label(app, text="Seleccione el modo de operación AES").pack(pady=10)
modos_operacion = [" ", "ECB", "CBC", "CFB", "OFB"]
clicked = StringVar()
menu_modos = OptionMenu(app, clicked, *modos_operacion).pack()
boton_modos = Button(app, text="Seleccionar modo", command=mostrarModo).pack(pady=10)
text_modos = Label(app, text="Ningun modo ha sido seleccionado...")
text_modos.pack(pady=20)
llaveLabel = Label(app, text="Llave (16 bytes): ").pack()
llaveVar = StringVar()
llaveEntry = Entry(app, textvariable=llaveVar, width=40).pack(padx=60, pady=10)
vectorLabel = Label(app, text="Vector (16 bytes):").pack()
vectorVar = StringVar()
vectorEntry = Entry(app, textvariable=vectorVar, width=40).pack(padx=60, pady=10)

botonDeArchivo = Button(app, text="Subir imagen", command=SubirImagen).pack(pady=25)

botonCifrar = Button(app, text="Cifrar", command=CifrarImagen).pack()
botonDescifrar = Button(app, text="Descifrar", command=DescifrarImagen).pack(pady=10)
label2 = Label(app, text="Esperando cifrar/descifrar imagen")
label2.pack(pady=20)

app.mainloop()