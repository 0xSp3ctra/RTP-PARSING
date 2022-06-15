import os

def conversion():
    file_raw = input("Nom du fichier à convertir :\n")
    file_wav = input("Nom du fichier de sortie :\n")   
    codec = input("Codec :\n")

    os.system(f"sox -t raw -r {codec} -b 16 -c 1 -L -e signed-integer {file_raw} {file_wav}")

conversion()