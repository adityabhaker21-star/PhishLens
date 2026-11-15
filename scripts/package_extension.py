"""Build the checked-in extension ZIP reproducibly from runtime files."""
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parents[1]
EXTENSION = ROOT / "extension"
RUNTIME_FILES = [
    "background.js", "content.js", "interstitial.html", "interstitial.js",
    "manifest.json", "overlay.js", "popup.html", "popup.js", "shield_main.js",
    "icons/icon16.png", "icons/icon48.png", "icons/icon128.png",
]

def package():
    target = ROOT / "PhishLens-Extension.zip"
    with ZipFile(target, "w", compression=ZIP_DEFLATED) as archive:
        for name in sorted(RUNTIME_FILES):
            entry = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = ZIP_DEFLATED
            entry.external_attr = 0o644 << 16
            archive.writestr(entry, (EXTENSION / name).read_bytes())
    return target

if __name__ == "__main__":
    print(package())
