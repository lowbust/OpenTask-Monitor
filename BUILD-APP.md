# GitHub: исходный код и готовый релиз отдельно

Публичная поставка 0.2.2:

- **opentask-monitor-0.2.2-source.zip** — исходный проект для Code.
- **OpenTaskMonitor-0.2.2-windows-x64-portable.zip** — внутри только OpenTaskMonitor.exe.

## Как опубликовать без локальной сборки

1. Создайте Public-репозиторий на GitHub.
2. Add file → Upload files: загрузите содержимое source ZIP, включая `.github`,
   не сам ZIP и не лишний уровень папки. В корне должны быть pyproject.toml,
   README.md, src, native, scripts, third_party и .github.
3. Actions → **Build Windows app** → Run workflow.
4. Дождитесь зелёной галочки, скачайте artifact **OpenTaskMonitor-release**.
5. В artifact находятся source ZIP, one-EXE portable ZIP и SHA256SUMS.txt.
6. Проверьте EXE на Windows. Откройте Releases → Draft a new release, выберите
   версию, прикрепите portable ZIP/EXE и контрольные суммы. Исходники можно также
   приложить, GitHub дополнительно сам генерирует Source code archives.
7. Пользователям отправляйте ссылку на Release. Они скачивают и запускают EXE,
   не устанавливают Python и не выполняют команды.

При push тега v* workflow создаёт **черновик** релиза с файлами. Проверяйте его
перед Publish. Artifact временный, публичный Release удобнее для распространения.
Готовый EXE не нужно коммитить в Code: он раздувает историю git и смешивает исходники
с бинарниками. Code — для кода, Releases — для собранной программы.

## Локальная воспроизводимая сборка для разработчика

На Linux: Python 3.11+, pip, MinGW-w64, доступ к официальным зависимостям.

```bash
python scripts/build_singlefile.py
python scripts/build_source_release.py
```

Скрипты выдадут два ZIP в release/. Проверка GUI выполняется отдельно под Wine/Windows.
Native extractor и source vendor miniz включены в репозиторий. Зависимости входят
в EXE, на первом запуске распаковываются в профиль пользователя. Подробно — README.

Старый folder/PyInstaller/Inno Setup workflow сохранён как **Legacy folder app and
installer (manual)** и не является текущим форматом выдачи. Он нужен только если
сопровождающий отдельно захочет установщик. Main workflow — один EXE в portable ZIP.
Не выдавайте неподтверждённую Windows сборку за production. Нет подписи EXE,
SmartScreen может предупредить; не отключайте защиту ради запуска.
