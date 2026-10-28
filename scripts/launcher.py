"""PyInstaller entry point (use an absolute import, not a relative package entry)."""
from opentask.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
