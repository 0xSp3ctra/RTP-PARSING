set PATH="C:\Program Files (x86)\sox-14-4-2"
sox --type raw --rate 8000 -e u-law %1.g711u %1.wav
sox --type raw --rate 8000 -e u-law %2.g711u %2.wav
sox -M %1.wav %2.wav %3.wav