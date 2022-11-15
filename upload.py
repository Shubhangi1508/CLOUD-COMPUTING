
from tkinter import *
from tkinter.ttk import *

from tkinter.filedialog import askopenfile

root = Tk()
root.geometry('200x100')
root = Tk()

def open_file():
	file = askopenfile(mode ='r', filetypes =[('Python Files', '*.csv')])
	if file is not None:
		content = file.read()
		print(content)

btn = Button(root, text ='Upload File Save from Cloud  ', command = lambda:open_file())
btn.pack(side = TOP, pady = 10)
Button(root, text="Quit", command=root.destroy).pack()
root.mainloop()

