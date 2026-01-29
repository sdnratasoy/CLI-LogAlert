# Log Analiz ve Uyarı Aracı

Go ile yazılmış, Docker destekli CLI log analiz aracı.

## Özellikler

- Dosya bazlı log analizi (auth.log, syslog, nginx, ufw.log, Windows Event Log)
- Gercek zamanlı izleme (tail modu)
- YAML/JSON ile konfigüre edilebilir kurallar
- CSV rapor cıktısı
- Renkli interaktif CLI menu

## Çalıştırma

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
