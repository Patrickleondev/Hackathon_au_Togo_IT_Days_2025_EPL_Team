# Vidéos de démonstration

Place ici les fichiers MP4 des démos référencées par le frontend :

- `demo.mp4`     — démo principale (page d'accueil)
- `demo-1.mp4`   — détection en temps réel d'un ransomware
- `demo-2.mp4`   — visite guidée de la console SOC
- `demo-3.mp4`   — analyse manuelle d'un fichier
- `demo-4.mp4`   — scan complet d'un répertoire

**Format recommandé :** H.264 / AAC, 1280×720, ≤ 5 Mo par clip.

**Tournage suggéré :** OBS Studio + bench local `make dev`, capture de l'écran à 30 fps, sortie WebM puis conversion MP4 :

```bash
ffmpeg -i demo-1.webm -c:v libx264 -crf 24 -preset slow -c:a aac -b:a 96k demo-1.mp4
```

Tant que les fichiers ne sont pas fournis, le poster SVG est affiché à la place.
