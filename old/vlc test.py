import vlc
i = vlc.Instance('--verbose 3')
print(i)
p = vlc.MediaPlayer('2005.mp3')
p.play()
