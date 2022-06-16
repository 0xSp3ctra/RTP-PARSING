import os

def conversion():  
    os.system(f"sox --type raw --rate 8000 -e u-law my_audio2.g711u my_audio2.wav")

conversion()