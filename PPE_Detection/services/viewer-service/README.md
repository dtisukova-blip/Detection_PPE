# Viewer Service

Runtime-сервис для простой очереди результатов проверки СИЗ.

Он принимает `target_kind=viewer` из маршрута Control Center, сохраняет запись локально и показывает оператору:

- аннотированное фото;
- время проверки;
- итог допуска или нарушения;
- недостающие обязательные СИЗ;
- checkpoint, worker и request id.

## Standalone Docker run

```bash
cd services/viewer-service
docker compose up --build
```

Для multi-host режима задайте реальный `VIEWER_LOCAL_URL`, доступный Control Center.
