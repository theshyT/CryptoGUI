import tkinter as tk
from tkinter import ttk, messagebox
from MyCryptoPackage import MyCaesarCipher as CC, RailFence as RF, \
    MonoAlphaCipher as MA, SimpleColumnarTransposition as CT, VernamCipher as VC,\
    CBC, ECB, CFB, OFB

from random import randint, shuffle
import random
LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


class Application(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self._frame = None
        self.switch_frame(Qn1)

    def switch_frame(self, frame_class):
        new_frame = frame_class(self)
        if self._frame is not None:
            self._frame.destroy()
        self._frame = new_frame
        self._frame.grid()


class Digitz(ttk.Entry):
    '''A Entry widget that only accepts digits'''
    def __init__(self, master=None, **kwargs):
        self.var = tk.StringVar(master)
        self.var.trace('w', self.validate)
        ttk.Entry.__init__(self, master, textvariable=self.var, **kwargs)
        self.get, self.set = self.var.get, self.var.set

    def validate(self, *args):
        value = self.get()
        if not value.isdigit():
            self.set(''.join(x for x in value if x.isdigit()))


class Qn2(tk.Frame):

    def __init__(self, master):
        """ Initialize the Frame """
        tk.Frame.__init__(self, master)
        self.grid()
        self.create_widgets()

    def create_widgets(self):
        # Title label
        self.instruction = tk.Label(self, text="Qn 2", font=("arial", 17, "bold"))
        self.instruction.grid(row=1, column=0, columnspan=2, padx=5, sticky=tk.W)

        # Method label
        self.method = tk.Label(self, text="Choose cipher:")
        self.method.grid(row=2, column=0, columnspan=2, padx=5, sticky=tk.W)

        # Method options
        self.var1 = tk.IntVar()
        self.cipherbox = ttk.Combobox(self, width=50, values=["Caesar Cipher", "Mono-alphabet Cipher", "Rail-Fence Technique", "Simple Columnar Transposition Technique", "Vernam Cipher"], state="readonly")
        self.cipherbox.grid(row=3, column=0, padx=5, sticky=tk.W)
        self.cipherbox.current(0)
        self.var1.set(0)  # Default option is Caesar Cipher
        self.cipherbox.bind('<<ComboboxSelected>>', self.select_cipher)

        # Key label
        self.instruction = tk.Label(self, text="Enter key:")
        self.instruction.grid(row=5, column=0, columnspan=2, padx=5, sticky=tk.W)

        # Key entry
        self.key = Digitz(self)
        self.key.grid(row=6, column=0, padx=5, ipadx=45, sticky=tk.W)

        # Temporary Key Entry for Vernam Cipher(one time pad)
        self.otp = ttk.Entry(self)
        self.otp.grid(row=6, column=0, padx=5, ipadx=45, sticky=tk.W)
        self.otp.grid_remove()

        self.gen = ttk.Button(self,text="Generate Random Key", command=self.generate_key)
        self.gen.grid(row=7, column=0, padx=5, pady=5, sticky=tk.W)

        # Message label
        self.instruction = tk.Label(self, text="Enter message/text: ")
        self.instruction.grid(row=9, column=0, columnspan=150, sticky=tk.W)

        # Message entry
        self.message = tk.Text(self, width=60, height=7)
        self.message.grid(row=10, column=0, padx=5, sticky=tk.W)

        # Encrypt/Decrypt Buttons

        self.encrypt_button = ttk.Button(self, text="Encrypt", command=self.encrypt_all)
        self.encrypt_button.grid(row=11, column=0, columnspan=1, pady=5, padx=5, sticky=tk.W)

        self.decrypt_button = ttk.Button(self, text="Decrypt", command=self.decrypt_all)
        self.decrypt_button.grid(row=11, column=0, columnspan=1, pady=5, padx=5, stick=tk.E)

        # Result label
        self.instruction = tk.Label(self, text="Result", font=("arial", 12, "bold"))
        self.instruction.grid(row=12, column=0, columnspan=2, padx=5, sticky=tk.W)

        # Result
        self.result = tk.Text(self, width=60, height=13, wrap=tk.WORD)
        self.result.grid(row=13, column=0, columnspan=3, padx=5, sticky=tk.W)

    def select_cipher(self,event):
        selected = self.cipherbox.get()
        if selected == "Caesar Cipher":
            self.var1.set(0)
            self.otp.grid_remove()
            self.otp.delete(0, tk.END)
            self.key.delete(0, tk.END)
            self.key.config(state="enabled")
            self.gen.config(state='enabled')
            self.result.delete(1.0, tk.END+"-1c")
        elif selected == "Mono-alphabet Cipher":
            self.var1.set(1)
            self.otp.grid()
            self.otp.delete(0, tk.END)
            self.key.delete(0, tk.END)
            self.key.config(state="disabled")
            self.gen.config(state='enabled')
            self.result.delete(1.0, tk.END + "-1c")
        elif selected == 'Rail-Fence Technique':
            self.var1.set(2)
            self.otp.grid_remove()
            self.otp.delete(0, tk.END)
            self.key.delete(0, tk.END)
            self.key.config(state="enabled")
            self.gen.config(state='disabled')
            self.result.delete(1.0, tk.END + "-1c")
        elif selected == 'Simple Columnar Transposition Technique':
            self.var1.set(3)
            self.otp.grid_remove()
            self.otp.delete(0, tk.END)
            self.key.delete(0, tk.END)
            self.key.config(state="enabled")
            self.gen.config(state='disabled')
            self.result.delete(1.0, tk.END + "-1c")
        elif selected == "Vernam Cipher":
            self.var1.set(4)
            self.otp.delete(0, tk.END)
            self.key.delete(0, tk.END)
            self.key.config(state="disabled")
            self.gen.config(state='disabled')
            self.otp.grid()
            self.result.delete(1.0, tk.END + "-1c")

    def generate_key(self):

        # Caesar
        if (self.var1.get()) == 0:
            self.key.delete(0, tk.END)
            self.otp.delete(0, tk.END)
            self.key.insert(0, randint(1, 64))
        # Mono-alpha
        if (self.var1.get()) == 1:
            self.key.delete(0, tk.END)
            self.otp.delete(0, tk.END)

            def get_random_key_ma():
                key = list(LETTERS)
                random.shuffle(key)
                str_key = ''.join(key)
                return str_key
            self.otp.insert(0, get_random_key_ma())
        # Rail Fence
        if (self.var1.get()) == 2:
            self.key.delete(0, tk.END)
            self.otp.delete(0, tk.END)
        # Simple-Columnar
        if (self.var1.get()) == 3:
            self.key.delete(0, tk.END)
            self.otp.delete(0, tk.END)
        # Vernam-Cipher
        if (self.var1.get()) == 4:
            self.key.delete(0, tk.END)
            self.otp.delete(0, tk.END)

    def encrypt_all(self):
        if (self.var1.get()) == 0:
            self.result.delete(1.0, tk.END)
            if validate_Caesar(self.key.get(), self.message.get(1.0, tk.END+'-1c').rstrip()) is True:
                self.result.insert(1.0, CC.encrypt(self.key.get(), self.message.get(1.0, tk.END+"-1c").rstrip()))

        if(self.var1.get()) == 1:
            self.result.delete(1.0, tk.END)
            if validate_MonoAlpha(self.otp.get(), self.message.get(1.0, tk.END+"-1c").rstrip()) is True:
                self.result.insert(1.0, MA.encrypt(self.otp.get(), self.message.get(1.0, tk.END+'-1c')).rstrip())

        if (self.var1.get()) == 2:
            self.result.delete(1.0, tk.END)
            if validate_RailFence(self.key.get(), self.message.get(1.0, tk.END+"-1c").rstrip()) is True:
                self.result.insert(1.0, RF.encrypt(self.key.get(), self.message.get(1.0, tk.END+'-1c').rstrip()))

        if (self.var1.get()) == 3:
            self.result.delete(1.0, tk.END)
            if validate_ColumnarTransposition(self.key.get(), self.message.get(1.0, tk.END+"-1c").rstrip()) is True:
                self.result.insert(1.0, CT.encrypt(self.key.get(), self.message.get(1.0, tk.END+'-1c').rstrip()))

        if (self.var1.get()) == 4:
            self.result.delete(1.0, tk.END)
            if validate_Vernam(self.otp.get(), self.message.get(1.0, tk.END + "-1c").rstrip()) == 1:
                self.result.insert(1.0, VC.encrypt(self.otp.get(), self.message.get(1.0, tk.END+"-1c").rstrip()))

    def decrypt_all(self):

        if (self.var1.get()) == 0:
            self.result.delete(1.0, tk.END)
            if validate_Caesar(self.key.get(), self.message.get(1.0,tk.END+'-1c').rstrip()) is True:
                self.result.insert(1.0, CC.decrypt(self.key.get(), self.message.get(1.0, tk.END+"-1c").rstrip()))

        if (self.var1.get()) == 1:
            self.result.delete(1.0, tk.END)
            if validate_MonoAlpha(self.otp.get(), self.message.get(1.0,tk.END+"-1c").rstrip()) is True:
                self.result.insert(1.0, MA.decrypt(self.otp.get(), self.message.get(1.0, tk.END+'-1c').rstrip()))

        if (self.var1.get()) == 2:
            self.result.delete(1.0, tk.END)
            if validate_RailFence(self.key.get(),self.message.get(1.0,tk.END+"-1c").rstrip()) is True:
                self.result.insert(1.0, RF.decrypt(self.key.get(), self.message.get(1.0, tk.END+'-1c').rstrip()))

        if (self.var1.get()) == 3:
            self.result.delete(1.0, tk.END)
            if validate_ColumnarTransposition(self.key.get(),self.message.get(1.0,tk.END+"-1c").rstrip()) is True:
                self.result.insert(1.0, CT.decrypt(self.key.get(), self.message.get(1.0, tk.END+"-1c").rstrip()))

        if (self.var1.get()) == 4:
            self.result.delete(1.0, tk.END)
            if validate_Vernam(self.otp.get(), self.message.get(1.0, tk.END + "-1c").rstrip()) == 1:
                self.result.insert(1.0, VC.decrypt(self.otp.get(), self.message.get(1.0, tk.END+"-1c").rstrip()))


class Qn1(tk.Frame):
    def __init__(self, master):
        tk.Frame.__init__(self, master)
        self.grid()
        self.create_widgets()

    def create_widgets(self):
        # Title label
        self.instruction = tk.Label(self, text="Qn 1", font=("arial", 17, "bold"))
        self.instruction.grid(row=0, column=0, columnspan=2, padx=5, sticky=tk.W)

        # Topic label
        self.topic = tk.Label(self, text="Choose Topic:")
        self.topic.grid(row=1, column=0, columnspan=2, padx=5, sticky=tk.W)
        # Topic options
        self.var2 = tk.IntVar()
        self.topicbox = ttk.Combobox(self, width=50,values=["Need for security", "Trusted systems and reference monitor", "Security models", "Security management practices", "Types of attacks"], state="readonly")
        self.topicbox.grid(row=2, column=0, padx=5, sticky=tk.W)
        self.topicbox.current(0)
        self.var2.set(0)  # Default topic is Need for Security
        self.topicbox.bind('<<ComboboxSelected>>', self.select_topic)

        # Result label
        self.instruction = tk.Label(self, text="", font=("arial", 12, "bold"))
        self.instruction.grid(row=3, column=0, columnspan=2, padx=5, sticky=tk.W)

        # Result
        self.result = tk.Text(self, width=75, height=15, wrap=tk.WORD,font=('arial', 11))
        self.result.grid(row=4, column=0, columnspan=3, padx=5, sticky=tk.W)
        self.result.insert(0.0, needforsecurity())
        self.result.config(state="disabled")

        self.instruction =tk.Label(self,text="Review question (fill in the blank or answer them appropriately)",
                                   font=('arial', 11, "bold"))
        self.instruction.grid(row=5, column=0, columnspan=2, padx=5, sticky=tk.W)

        self.question = tk.Text(self, width=75, height=4, wrap=tk.WORD)
        self.question.grid(row=8, column=0, columnspan=3, padx=5, sticky=tk.W)
        self.question.insert(1.0, review1())
        self.question.config(state="disabled")

        self.instruction = tk.Label(self,text="Answer:", font=('arial', 11, 'bold'))
        self.instruction.grid(row=9, column=0, columnspan=3, padx=5, sticky=tk.W)
        self.answer = tk.Text(self, width=75, height=2, wrap=tk.WORD)
        self.answer.grid(row=10, column=0, columnspan=3, padx=5, sticky=tk.W)

        self.submit_button = ttk.Button(self, text="Submit", command=self.submit_all)
        self.submit_button.grid(row=13, column=0, columnspan=3, pady=5,padx=5, sticky=tk.E)
        self.getimg_button = ttk.Button(self, text="Get illustration", command=self.imgwindow)
        self.getimg_button.grid(row=13, column=0, columnspan=3, pady=5, padx=5, sticky=tk.W )

    def select_topic(self, event):
        selected = self.topicbox.get()
        if selected == "Need for security":
            self.var2.set(0)
            self.result.config(state="normal")
            self.result.delete(1.0, tk.END + "-1c")
            self.answer.delete(1.0, tk.END+"-1c")
            self.result.insert(1.0, needforsecurity())
            self.result.config(state="disabled")
            self.question.config(state="normal")
            self.question.delete(1.0, tk.END + "-1c")
            self.question.insert(1.0, review1())
            self.question.config(state="disabled")
            self.getimg_button.config(state="normal")

        if selected == "Trusted systems and reference monitor":
            self.var2.set(1)
            self.result.config(state="normal")
            self.result.delete(1.0, tk.END + "-1c")
            self.answer.delete(1.0, tk.END+"-1c")
            self.result.insert(1.0, trustedsys())
            self.result.config(state="disabled")
            self.question.config(state="normal")
            self.question.delete(1.0, tk.END + "-1c")
            self.question.insert(1.0, review2())
            self.question.config(state="normal")
            self.getimg_button.config(state="normal")

        if selected == 'Security models':
            self.var2.set(2)
            self.result.config(state="normal")
            self.result.delete(1.0, tk.END + "-1c")
            self.answer.delete(1.0,tk.END+"-1c")
            self.result.insert(1.0,securitymodels())
            self.result.config(state="disabled")
            self.question.config(state="normal")
            self.question.delete(1.0, tk.END + "-1c")
            self.question.insert(1.0, review3())
            self.question.config(state="disabled")
            self.getimg_button.config(state="disabled")

        if selected == 'Security management practices':
            self.var2.set(3)
            self.result.config(state="normal")
            self.result.delete(1.0, tk.END + "-1c")
            self.answer.delete(1.0,tk.END+"-1c")
            self.result.insert(0.0,securitymgmmod())
            self.result.config(state="disabled")
            self.question.config(state="normal")
            self.question.delete(1.0, tk.END + "-1c")
            self.question.insert(1.0, review4())
            self.question.config(state="disabled")
            self.getimg_button.config(state="disabled")

        if selected == "Types of attacks":
            self.var2.set(4)
            self.result.config(state="normal")
            self.result.delete(1.0, tk.END + "-1c")
            self.answer.delete(1.0, tk.END+"-1c")
            self.result.insert(0.0, typeatk())
            self.result.config(state="disabled")
            self.question.config(state="normal")
            self.question.delete(1.0, tk.END + "-1c")
            self.question.insert(1.0, review5())
            self.question.config(state="disabled")
            self.getimg_button.config(state="normal")

    def imgwindow(self):
        temp = tk.Toplevel()
        canvas = tk.Canvas(temp, width=390,height=200)
        canvas.grid()
        if self.topicbox.get() == "Trusted systems and reference monitor":
            img = tk.PhotoImage(file='assets/referencemonitor.PNG')
            canvas.create_image(50, 10, image=img, anchor=tk.NW)
            canvas.img = img
        if self.topicbox.get() == "Need for security":
            img = tk.PhotoImage(file='assets/needforsec.PNG')
            canvas.create_image(50, 10, image=img, anchor=tk.NW)
            canvas.img = img
        if self.topicbox.get() == "Types of attacks":
            img = tk.PhotoImage(file='assets/activeatks.PNG')
            canvas.create_image(50, 10, image=img, anchor=tk.NW)
            canvas.img = img
        temp.title("illustration-Qn1")
        temp.resizable(False, False)
        temp.mainloop()

    def submit_all(self):
        if (self.var2.get()) == 0:
            a = self.answer.get(1.0,tk.END+"-1c").rstrip()
            if a == "":
                pass
            elif a == "secure" or a == "SECURE" or a == "Secure":
                messagebox.showinfo("Congrats!", "Answer is correct!")
            else:
                messagebox.showerror('Error!', "Answer is wrong!")

        if(self.var2.get()) == 1:
            a = self.answer.get(1.0, tk.END+"-1c").rstrip()
            if a == "responsible" or a == "RESPONSIBLE" or a == "Responsible":
                messagebox.showinfo("Congrats!", "Answer is correct!")
            else:
                messagebox.showerror('Error!', "Answer is wrong!")

        if (self.var2.get()) == 2:
            a = self.answer.get(1.0, tk.END+"-1c").rstrip()
            if a == "hiding" or a == "HIDING" or a == "Hiding":
                messagebox.showinfo("Congrats!", "Answer is correct!")
            else:
                messagebox.showerror('Error!', "Answer is wrong!")

        if (self.var2.get()) == 3:
            a = self.answer.get(1.0, tk.END+"-1c").rstrip()
            if a == "no" or a == "No" or a == "NO":
                messagebox.showinfo("Congrats!", "Answer is correct!")
            else:
                messagebox.showerror('Error!', "Answer is wrong!")

        if (self.var2.get()) == 4:
            a = self.answer.get(1.0, tk.END+"-1c").rstrip()
            if a == "active" or a == "ACTIVE" or a == "active attack":
                messagebox.showinfo("Congrats!", "Answer is correct!")
            else:
                messagebox.showerror('Error!', "Answer is wrong!")


class Qn3(tk.Frame):
    def __init__(self, master):
        tk.Frame.__init__(self, master)
        self.grid()
        self.create_widgets()

    def create_widgets(self):

        # Title label
        self.instruction = tk.Label(self, text="Qn 3", font=("arial", 17, "bold"))
        self.instruction.grid(row=1, column=0, columnspan=2, padx=5, sticky=tk.W)

        # Method label
        self.method = tk.Label(self, text="Choose cipher modes:")
        self.method.grid(row=2, column=0, columnspan=2, padx=5, sticky=tk.W)

        # Method options
        self.var3 = tk.IntVar()
        self.cipherbox = ttk.Combobox(self,width=50,values=["AES-ECB", "AES-CBC", "AES-CFB", "AES-OFB"], state="readonly")
        self.cipherbox.grid(row=3, column=0, padx=5, sticky=tk.W)
        self.cipherbox.current(0)
        self.var3.set(0)
        self.cipherbox.bind('<<ComboboxSelected>>', self.select_mode)

        # Key label
        self.instruction = tk.Label(self, text="Choose key size:")
        self.instruction.grid(row=5, column=0, columnspan=2, padx=5, sticky=tk.W)

        # Key drop-down menu
        self.var4 = tk.IntVar()
        self.keysize = ttk.Combobox(self, width=50, values=['128 bits', '192 bits', '256 bits'], state="readonly")
        self.keysize.grid(row=6, column=0, padx=5,sticky=tk.W)
        self.keysize.current(0)
        self.var4.set(0)
        self.keysize.bind("<<ComboboxSelected>>", self.select_size)

        self.instruction = tk.Label(self, text="Key:")
        self.instruction.grid(row=7, column=0, columnspan=2, padx=5, sticky=tk.W)
        #Key

        self.key = Digitz(self)
        self.key.grid(row=8, column=0, padx=5, ipadx=45, sticky=tk.W)

        self.gen = ttk.Button(self,text="Generate Random Key", command=self.generate_key)
        self.gen.grid(row=9, column=0, padx=5, pady=5, sticky=tk.W)

        # Message label
        self.instruction = tk.Label(self, text="Enter message/text: ")
        self.instruction.grid(row=10, column=0, columnspan=150, sticky=tk.W)

        # Message entry
        self.message = tk.Text(self, width=60, height=7)
        self.message.grid(row=11, column=0, padx=5, sticky=tk.W)

        # Encrypt/Decrpyt Buttons

        self.encrypt_button = ttk.Button(self, text="Encrypt", command=self.encrypt_all)
        self.encrypt_button.grid(row=12, column=0, columnspan=1, pady=5, padx=5, sticky=tk.W)

        self.decrypt_button = ttk.Button(self, text="Decrypt", command=self.decrypt_all)
        self.decrypt_button.grid(row=12, column=0, columnspan=1, pady=5, padx=5, sticky=tk.E)
        self.decrypt_button.config(state=tk.DISABLED)
        # Result label
        self.instruction = tk.Label(self, text="Result", font=("arial", 12, "bold"))
        self.instruction.grid(row=13, column=0, columnspan=2, padx=5, sticky=tk.W)

        # Result
        self.result = tk.Text(self, width=60, height=10, wrap=tk.WORD)
        self.result.grid(row=14, column=0, columnspan=3, padx=5, sticky=tk.W)

    def select_mode(self, event):
        selected = self.cipherbox.get()
        if selected == "AES-ECB":
            self.var3.set(0)
            self.key.delete(0, tk.END)
            self.decrypt_button.config(state=tk.DISABLED)
            self.result.delete(1.0, tk.END + "-1c")
        elif selected == "AES-CBC":
            self.var3.set(1)
            self.key.delete(0, tk.END)
            self.decrypt_button.config(state=tk.DISABLED)
            self.result.delete(1.0, tk.END + "-1c")
        elif selected == 'AES-CFB':
            self.var3.set(2)
            self.key.delete(0, tk.END)
            self.decrypt_button.config(state=tk.DISABLED)
            self.result.delete(1.0, tk.END + "-1c")
        elif selected == 'AES-OFB':
            self.var3.set(3)
            self.key.delete(0, tk.END)
            self.decrypt_button.config(state=tk.DISABLED)
            self.result.delete(1.0, tk.END + "-1c")

    def select_size(self, event):
        selected = self.keysize.get()
        if selected == "128 bits":
            self.var4.set(0)
            self.key.delete(0, tk.END)
            self.result.delete(1.0, tk.END + "-1c")

        elif selected == "192 bits":
            self.var4.set(1)
            self.key.delete(0, tk.END)
            self.result.delete(1.0, tk.END + "-1c")

        elif selected == "256 bits":
            self.var4.set(2)
            self.key.delete(0, tk.END)
            self.result.delete(1.0, tk.END + "-1c")

    def generate_key(self):
        if self.var4.get() == 0:
            self.key.delete(0, tk.END)
            self.key128 = random_with_N_digits(16)
            self.key.insert(0, self.key128)
            self.decrypt_button.config(state="disabled")
        elif self.var4.get() == 1:
            self.key.delete(0, tk.END)
            self.key192 = random_with_N_digits(24)
            self.key.insert(0, self.key192)
            self.decrypt_button.config(state="disabled")
        elif self.var4.get() == 2:
            self.key.delete(0, tk.END)
            self.key256 = random_with_N_digits(32)
            self.key.insert(0, self.key256)
            self.decrypt_button.config(state="disabled")

    def encrypt_all(self):
        # ECB
        if self.var3.get() == 0:
            try:
                ciphertext_file = 'ECB_ciphertext.bin'
                self.result.delete(1.0, tk.END)
                if self.var4.get() == 0:
                    self.msg = self.message.get(1.0, tk.END + "-1c").rstrip()
                    if len(self.key.get()) != 16 or self.msg == '':
                        messagebox.showerror("Error!", "key must be 128 bits! and textbox should noy be empty!")
                    else:
                        self.result.insert(0.0, ECB.encrypt(self.key.get().encode('utf-8'), self.msg.encode('utf-8'),
                                                            ciphertext_file))
                        self.decrypt_button.config(state="normal")
                elif self.var4.get() == 1:
                    self.msg = self.message.get(1.0, tk.END + "-1c").rstrip()
                    if len(self.key.get()) != 24:
                        messagebox.showerror("Error!", "key must be 192 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, ECB.encrypt(self.key.get().encode('utf-8'), self.msg.encode('utf-8'),
                                                            ciphertext_file))
                        self.decrypt_button.config(state="normal")
                else:
                    self.msg = self.message.get(1.0, tk.END + "-1c").rstrip()
                    if len(self.key.get()) != 32:
                        messagebox.showerror("Error!", "key must be 256 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, ECB.encrypt(self.key.get().encode('utf-8'), self.msg.encode('utf-8'),
                                                            ciphertext_file))
                        self.decrypt_button.config(state="normal")
            except ValueError:
                messagebox.showerror("Error!", "Key is wrong!")
        # CBC
        if self.var3.get() == 1:
            try:
                ciphertext_file = 'CBC_ciphertext.bin'
                self.result.delete(1.0, tk.END)
                if self.var4.get() == 0:
                    self.msg = self.message.get(1.0, tk.END+"-1c").rstrip()
                    if len(self.key.get()) != 16:
                        messagebox.showerror("Error!", "key must be 128 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, CBC.encrypt(self.key.get().encode('utf-8'), self.msg.encode('utf-8'),
                                                            ciphertext_file))
                        self.decrypt_button.config(state="normal")
                elif self.var4.get() == 1:
                    self.msg = self.message.get(1.0, tk.END+"-1c").rstrip()
                    if len(self.key.get()) != 24:
                        messagebox.showerror("Error!", "key must be 192 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, CBC.encrypt(self.key.get().encode('utf-8'), self.msg.encode('utf-8'),
                                                            ciphertext_file))
                        self.decrypt_button.config(state="normal")
                else:
                    self.msg = self.message.get(1.0, tk.END+"-1c").rstrip()
                    if len(self.key.get()) != 32:
                        messagebox.showerror("Error!", "key must be 128 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, CBC.encrypt(self.key.get().encode('utf-8'), self.msg.encode('utf-8'),
                                                            ciphertext_file))
                        self.decrypt_button.config(state="normal")
            except ValueError:
                messagebox.showerror("Error!", "Key is wrong!")
        # CFB
        if self.var3.get() == 2:
            try:
                ciphertext_file = 'CFB_ciphertext.bin'
                self.result.delete(1.0, tk.END)
                if self.var4.get() == 0:
                    self.msg = self.message.get(1.0, tk.END+"-1c").rstrip()
                    if len(self.key.get()) != 16:                        messagebox.showerror("Error!", "key must be 128 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, CFB.encrypt(self.key.get().encode('utf-8'),self.msg.encode('utf-8'),
                                                            ciphertext_file))
                        self.decrypt_button.config(state="normal")
                elif self.var4.get() == 1:
                    self.msg = self.message.get(1.0, tk.END+"-1c").rstrip()
                    if len(self.key.get()) != 24:
                        messagebox.showerror("Error!", "key must be 192 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, CFB.encrypt(self.key.get().encode('utf-8'),self.msg.encode('utf-8'),
                                                           ciphertext_file))
                        self.decrypt_button.config(state="normal")
                else:
                    self.msg = self.message.get(1.0,tk.END+"-1c").rstrip()
                    if len(self.key.get()) != 32:
                        messagebox.showerror("Error!", "key must be 256 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, CFB.encrypt(self.key.get().encode('utf-8'),self.msg.encode('utf-8'),
                                                            ciphertext_file))
                        self.decrypt_button.config(state="normal")
            except ValueError:
                messagebox.showerror("Error!", "Key is wrong!")
        # OFB
        if self.var3.get() == 3:
            try:
                ciphertext_file = 'OFB_ciphertext.bin'
                self.result.delete(1.0,tk.END)
                if self.var4.get() == 0:
                    self.msg = self.message.get(1.0, tk.END+"-1c").rstrip()
                    if len(self.key.get()) != 16:
                        messagebox.showerror("Error!", "key must be 128 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, OFB.encrypt(self.key.get().encode('utf-8'),self.msg.encode('utf-8'),
                                                            ciphertext_file))
                        self.decrypt_button.config(state="normal")
                elif self.var4.get() == 1:
                    self.msg = self.message.get(1.0, tk.END+"-1c").rstrip()
                    if len(self.key.get()) != 24:
                        messagebox.showerror("Error!", "key must be 192 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, OFB.encrypt(self.key.get().encode('utf-8'), self.msg.encode('utf-8'),
                                                            ciphertext_file))
                        self.decrypt_button.config(state="normal")
                else:
                    self.msg = self.message.get(1.0,tk.END+"-1c").rstrip()
                    if len(self.key.get()) != 32:
                        messagebox.showerror("Error!", "key must be 256 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, OFB.encrypt(self.key.get().encode('utf-8'), self.msg.encode('utf-8'),
                                                            ciphertext_file))
                        self.decrypt_button.config(state="normal")
            except ValueError:
                messagebox.showerror("Error!", "Key is wrong!")

    def decrypt_all(self):
        # ECB
        if self.var3.get() == 0:
            try:
                ciphertext_file = 'ECB_ciphertext.bin'
                self.result.delete(1.0,tk.END+"-1c")
                if self.var4.get() == 0:
                    self.output = self.result.get(1.0, tk.END+"-1c").rstrip()
                    if len(self.key.get()) != 16:
                        messagebox.showerror("Error!", "key must be 128 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, ECB.decrypt(self.key.get().encode('utf-8'), ciphertext_file))
                        self.decrypt_button.config(state="disabled")
                elif self.var4.get() == 1:
                    self.msg = self.message.get(1.0, tk.END + "-1c").rstrip()
                    if len(self.key.get()) != 24:
                        messagebox.showerror("Error!", "key must be 192 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, ECB.decrypt(self.key.get().encode('utf-8') ,ciphertext_file))
                        self.decrypt_button.config(state="disabled")
                else:
                    self.msg = self.message.get(1.0, tk.END + "-1c").rstrip()
                    if len(self.key.get()) != 32:
                        messagebox.showerror("Error!", "key must be 256 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, ECB.decrypt(self.key.get().encode('utf-8'), ciphertext_file))
                        self.decrypt_button.config(state="disabled")
            except ValueError:
                messagebox.showerror("Error!", "Key is wrong!")
        # CBC
        if self.var3.get() == 1:
            try:
                ciphertext_file ='CBC_ciphertext.bin'
                self.result.delete(1.0,tk.END+'-1c')
                if self.var4.get() == 0:
                    if len(self.key.get()) != 16:
                        messagebox.showerror("Error!", "key must be 128 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, CBC.decrypt(self.key.get().encode('utf-8'), ciphertext_file))
                        self.decrypt_button.config(state="disabled")
                elif self.var4.get() == 1:
                    if len(self.key.get()) != 24:
                        messagebox.showerror("Error!", "key must be 192 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, CBC.decrypt(self.key.get().encode('utf-8'), ciphertext_file))
                        self.decrypt_button.config(state="disabled")
                elif self.var4.get() == 2:
                    if len(self.key.get()) != 32:
                        messagebox.showerror("Error!", "key must be 256 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, CBC.decrypt(self.key.get().encode('utf-8'), ciphertext_file))
                        self.decrypt_button.config(state="disabled")
            except ValueError:
                messagebox.showerror("Error!", "Key is wrong!")

        # CFB
        if self.var3.get() == 2:
            try:
                ciphertext_file ='CFB_ciphertext.bin'
                self.result.delete(1.0, tk.END+"-1c")
                if self.var4.get() == 0:
                    if len(self.key.get()) != 16:
                        messagebox.showerror("Error!", "key must be 128 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, CFB.decrypt(self.key.get().encode('utf-8'),ciphertext_file))
                        self.decrypt_button.config(state="disabled")
                elif self.var4.get() == 1:
                    if len(self.key.get()) != 24:
                        messagebox.showerror("Error!", "key must be 192 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, CFB.decrypt(self.key.get().encode('utf-8'), ciphertext_file))
                        self.decrypt_button.config(state="disabled")
                elif self.var4.get() == 2:
                    if len(self.key.get()) != 32:
                        messagebox.showerror("Error!", "key must be 256 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0,CFB.decrypt(self.key.get().encode('utf-8'), ciphertext_file))
                    self.decrypt_button.config(state="disabled")
            except ValueError:
                messagebox.showerror("Error!", "Key is wrong!")
        # OFB
        if self.var3.get() == 3:
            try:
                ciphertext_file ='OFB_ciphertext.bin'
                self.result.delete(1.0, tk.END+"-1c")
                if self.var4.get() == 0:
                    if len(self.key.get()) != 16:
                        messagebox.showerror("Error!", "key must be 128 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, OFB.decrypt(self.key.get().encode('utf-8'), ciphertext_file))
                        self.decrypt_button.config(state="disabled")
                elif self.var4.get() == 1:
                    if len(self.key.get()) != 24:
                        messagebox.showerror("Error!", "key must be 192 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, OFB.decrypt(self.key.get().encode('utf-8'), ciphertext_file))
                    self.decrypt_button.config(state="disabled")
                elif self.var4.get() == 2:
                    if len(self.key.get()) != 32:
                        messagebox.showerror("Error!", "key must be 256 bits!")
                    elif self.msg == '':
                        messagebox.showerror("Error!", "textbox should not be empty!")
                    else:
                        self.result.insert(1.0, OFB.decrypt(self.key.get().encode('utf-8'), ciphertext_file))
                        self.decrypt_button.config(state="disabled")
            except ValueError:
                messagebox.showerror("Error!", "Key is wrong!")


def random_with_N_digits(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return randint(range_start, range_end)


def validate_Caesar(key,text):
    try:
        if key == '':
            messagebox.showerror("Error!", "Key is empty!")
            return False
        if text == '':
            messagebox.showerror("Error!", "Textbox is empty!")
            return False
        if int(key) > 64 or int(key) == 0:
            messagebox.showerror("Error!", "Key should not be 0 or larger than 64")
            return False
        else:
            return True
    except IndexError:
        messagebox.showerror("Error!", "Index Error!")


def validate_MonoAlpha(key, text):
    def checkvalidkey(keyz):
        keyList = list(keyz.upper())
        letterslist = list(LETTERS)
        keyList.sort()
        letterslist.sort()
        if keyList != letterslist:
            return False
        else:
            return True
    try:
        if key == '':
            messagebox.showerror("Error!", "Key is empty!")
            return False
        if key.islower():
            messagebox.showerror("Error!", "Key should be of uppercase letters only")
            return False
        mixed_case = not key.islower() and not key.isupper()
        if mixed_case:
            messagebox.showerror("Error!", "Key should be of uppercase letters only")
            return False
        if text == '':
            messagebox.showerror("Error!", "Textbox is empty!")
            return False
        if len(key) == 0 or len(key) != 26:
            messagebox.showerror("Error!", "Key should not contain any numbers and should be of 26 distinct letters")
            return False
        if checkvalidkey(key) is False:
            messagebox.showerror("Error!", "Key is not valid! Remove any duplicate letters ")
            return False
        else:
            return True
    except IndexError:
        messagebox.showerror("Error!", "Index Error!")


def validate_RailFence(key,text):
    try:
        if key == '':
            messagebox.showerror("Error!", "Key is emtpy!")
            return False
        if text == '':
            messagebox.showerror("Error!", "Textbox is empty!")
            return False
        if int(key) >= len(text) or int(key) <= 1:
            messagebox.showerror("Error!", "Key should be greater than 1 and must be smaller than the length of text !")
            return False
        else:
            return True
    except IndexError:
        messagebox.showerror("Error! ", "Index Error!")


def validate_ColumnarTransposition(key, text):
    try:
        if key == "":
            messagebox.showerror("Error! ", "Key is empty!")
            return False
        if text == '':
            messagebox.showerror("Error! ", "Textbox is empty!")
            return False
        if int(key) <= 1:
            messagebox.showerror("Error! ", "Key should be greater than 1")
            return False
        if len(text) <= int(key):
            messagebox.showerror("Error! ", "Key should not be greater than or equal to the length of the text!")
            return False
        else:
            return True
    except IndexError:
        messagebox.showerror("Error!", "Index Error!")


def validate_Vernam(key, text):
    try:
        if key == '':
            messagebox.showerror("Error!", "Key is empty!")
            return False
        if text == '':
            messagebox.showerror("Error!", "Textbox is empty!")
            return False
        if not key.isalpha():
            messagebox.showerror("Error! ", "Key should be of letters only")
            return False
        if not text.isalpha():
            messagebox.showerror("Error!", "Invalid text format - Text should not consist of any space or numbers")
            return False
        if len(text) != len(key):
            messagebox.showerror("Error!", "Key length should be the same as the length of text")
            return False
        else:
            return 1
    except IndexError:
        messagebox.showerror("Error!", "Index Error!")


def needforsecurity():
    return "Data transmitted in clear text  may not be secure.\n\nIn today’s world, we use the Internet for many purposes.\n\nWe use the Internet to email our friends or \
colleagues, We use the Internet to WhatsApp our families and clients,We also use the Internet to make \
purchases or for banking.\n\nIf we send confidential information in the clear, \
i.e. unprotected,The confidential information is not secure and can be compromised."


def review1():
    return "If we send confidential information in the clear, i.e. unprotected,The confidential \
information is not ________ and can be compromised."


def trustedsys():
    return "What is a trusted system? \n\nA trusted system is a computer system that can be trusted to a specified extent.\
It is able to enforce a specified security policy\
\n\nWhat is a reference monitor?\n\nA reference monitor is an entity at the heart of a computer system.\nIt is\
responsible for all decisions related to enforcing access controls\n\n3 Characteristics of reference monitor\n\n1.Should be tamperproof\
\n2.Should always be invoked\n3.Should be small enough so that it can be independently tested. "


def review2():
    return"Reference monitor is _________ for all decisions related to enforcing access controls."


def securitymodels():
    return "There are 4 approaches to implement a security model\
\n\n1.No Security(security(as-is)),it means using the system with the default security configuration\
\n\n2.Security through obscurity, it means securing information by hiding\
\n\n3.Host Security, it means providing security by protecting the host\
\n\n4.Network Security, it means protecting the network by encrypting communication channel. "

def review3():
    return"Security through obscurity, it refers to securing by __________"


def securitymgmmod():
    return"There are 4 key characteristics of a good security policy:\
\n\n1. Affordability: the security policy should not be too costly and incur too much effort to implement\
\n\n2.Functionality: there should be available security mechanism to support the security policy\
\n\n3.Cultural issues: the security policy should gel with people’s expectations,working style and beliefs\
\n\n4. Legality: the policy should meet legal requirements,eg. use of 2FA in internet banking."


def review4():
    return "Is Efficiency part of the 4 characteristics of a good security policy?(Yes/No)"


def typeatk():
    return"Attacks can be classified as passive attacks or active attacks.\
\n\nPassive attacks(interception):\n-Release of message contents,it means the recipient of a message can be an attacker \
and send message to someone against sender's wish\n-Traffic analysis,the attacker sniff the network and attempt to \
analyse encoded message\n\nActive attacks:\n-1.Interruption attack,affects availability of system\n-2.Modification attack,\
affects integrity of message which consist of\n     -3.Replay attacks(capture and resend message)\n     \
-4.Alteration(change original message)\n\n-5.Fabrication,affects the \
authenticity of the message"


def review5():
    return"Is Replay attack an active or passive attack?"


def help():
    messagebox.showinfo("Help", "You can refer to the UserGuide.docx for any problems you faced using the app")


root = Application()
root.title("OngJingQuan CryptoApp")
root.geometry("630x580")
root.resizable(False, False)


my_menu = tk.Menu(root)
root.config(menu=my_menu)

file_menu = tk.Menu(my_menu, tearoff=0)
my_menu.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="Exit", command=root.quit)

mode_menu = tk.Menu(my_menu, tearoff=0)
my_menu.add_cascade(label="Mode", menu=mode_menu)
mode_menu.add_command(label='Qn1', command=lambda: root.switch_frame(Qn1))
mode_menu.add_command(label='Qn2', command=lambda: root.switch_frame(Qn2))
mode_menu.add_command(label='Qn3', command=lambda: root.switch_frame(Qn3))

my_menu.add_command(label="Help", command=lambda: help())
root.mainloop()

