# Log Analiz ve Uyari Araci

Go ile yazilmis, Docker destekli CLI log analiz aracı.

## Ozellikler

- Dosya bazli log analizi (auth.log, syslog, nginx, ufw.log, Windows Event Log)
- Gercek zamanli izleme (tail modu)
- YAML/JSON ile konfigüre edilebilir kurallar
- CSV rapor ciktisi
- Renkli interaktif CLI menu

## Calistirma

### Docker ile

```bash
docker build -t loganalyzer .
docker run -it --rm loganalyzer
```

### Docker Compose ile

```bash
docker-compose up -d
docker-compose exec loganalyzer ./loganalyzer
```
