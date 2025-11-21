import tkinter as tk
from tkinter import scrolledtext, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Génération des clés RSA (publique et privée)
# Génération de la clé privée
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Clé publique
public_key = private_key.public_key()


# Fonction pour chiffrer le message
def encrypt_message():
    message = txt_input.get("1.0", tk.END).strip().encode()
    if not message:
        messagebox.showwarning("Attention", "Veuillez entrer un message")
        return
    
    # Chiffrement du message avec la clé publique
    global ciphertext
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    txt_output.delete("1.0", tk.END)
    txt_output.insert(tk.END, str(ciphertext))
    messagebox.showinfo("Succès", "Message chiffré !")


# Fonction pour déchiffrer le message
def decrypt_message():
    try:
        # Déchiffrement du message avec la clé privée
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        txt_output.delete("1.0", tk.END)
        txt_output.insert(tk.END, plaintext.decode())
        messagebox.showinfo("Succès", "Message déchiffré !")
    except:
        messagebox.showerror("Erreur", "Impossible de déchiffrer. Chiffrez d'abord le message.")


# Fonction pour signer le message
def sign_message():
    message = txt_input.get("1.0", tk.END).strip().encode()
    if not message:
        messagebox.showwarning("Attention", "Veuillez entrer un message")
        return
    
    global signature
    # Signature numérique (pour vérifier l'intégrité + authenticité)
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    txt_output.delete("1.0", tk.END)
    txt_output.insert(tk.END, str(signature))
    messagebox.showinfo("Succès", "Message signé !")


# Fonction pour vérifier la signature
def verify_signature():
    message = txt_input.get("1.0", tk.END).strip().encode()
    if not message:
        messagebox.showwarning("Attention", "Veuillez entrer un message")
        return
    
    try:
        # Vérification de la signature avec la clé publique
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        messagebox.showinfo("✔ Succès", "Le message est authentique et n'a pas été modifié.")
    except:
        messagebox.showerror("❌ Erreur", "Le message a été modifié ou la signature est fausse.")


# ------------------ Interface Tkinter ------------------ #
root = tk.Tk()
root.title("Chiffrement RSA avec Signature")
root.geometry("700x500")

lbl_input = tk.Label(root, text="Entrez votre message :")
lbl_input.pack()

txt_input = scrolledtext.ScrolledText(root, width=80, height=5)
txt_input.pack()

btn_encrypt = tk.Button(root, text="Chiffrer le message", command=encrypt_message)
btn_encrypt.pack(pady=5)

btn_decrypt = tk.Button(root, text="Déchiffrer le message", command=decrypt_message)
btn_decrypt.pack(pady=5)

btn_sign = tk.Button(root, text="Signer le message", command=sign_message)
btn_sign.pack(pady=5)

btn_verify = tk.Button(root, text="Vérifier la signature", command=verify_signature)
btn_verify.pack(pady=5)

lbl_output = tk.Label(root, text="Résultat :")
lbl_output.pack()

txt_output = scrolledtext.ScrolledText(root, width=80, height=10)
txt_output.pack()

root.mainloop()
