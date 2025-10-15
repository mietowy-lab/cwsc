import os
import subprocess
from datetime import datetime

# === KONFIGURACJA ===
BASE_DIR = r"C:\Users\Marek\cwsc"
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
REPO_PATH = BASE_DIR  # to samo repo co GitHub
BRANCH = "main"

def get_latest_report_folder():
    """Zwraca najnowszy folder w reports/"""
    try:
        folders = [
            os.path.join(REPORTS_DIR, d)
            for d in os.listdir(REPORTS_DIR)
            if os.path.isdir(os.path.join(REPORTS_DIR, d))
        ]
        if not folders:
            print("❌ Brak folderów w katalogu reports/")
            return None
        return max(folders, key=os.path.getmtime)
    except Exception as e:
        print(f"❌ Błąd podczas szukania folderów: {e}")
        return None

def run_cmd(cmd, cwd=None):
    """Uruchamia polecenie systemowe i zwraca wynik"""
    print(f"🔄 Wykonuję: {cmd}")
    result = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, shell=True)
    if result.returncode != 0:
        print(f"❌ Błąd: {result.stderr.strip()}")
        if result.stdout.strip():
            print(f"📝 Output: {result.stdout.strip()}")
    else:
        if result.stdout.strip():
            print(f"✅ {result.stdout.strip()}")
        else:
            print("✅ Polecenie wykonane pomyślnie")
    return result

def sync_index_to_github():
    print("🚀 Rozpoczynam synchronizację z GitHub...")
    print("=" * 50)
    
    # Sprawdź czy katalog reports istnieje
    if not os.path.exists(REPORTS_DIR):
        print(f"❌ Katalog reports nie istnieje: {REPORTS_DIR}")
        return False
    
    latest_folder = get_latest_report_folder()
    if not latest_folder:
        return False
    
    folder_name = os.path.basename(latest_folder)
    print(f"📁 Najnowszy folder: {folder_name}")
    
    source_file = os.path.join(latest_folder, "index.html")
    dest_file = os.path.join(REPO_PATH, "index.html")

    if not os.path.exists(source_file):
        print(f"❌ Nie znaleziono pliku: {source_file}")
        return False

    # Sprawdź czy to repo git
    if not os.path.exists(os.path.join(REPO_PATH, ".git")):
        print(f"❌ {REPO_PATH} nie jest repozytorium Git")
        return False

    try:
        # Kopiuj plik
        print(f"📄 Kopiuję plik...")
        with open(source_file, "rb") as src, open(dest_file, "wb") as dst:
            dst.write(src.read())
        print(f"✅ Skopiowano: {source_file} → {dest_file}")

        # Sprawdź status git
        print("\n📊 Status repozytorium:")
        run_cmd("git status --porcelain", cwd=REPO_PATH)

        # Git add
        print("\n📤 Dodaję zmiany do Git...")
        result_add = run_cmd("git add index.html", cwd=REPO_PATH)
        
        if result_add.returncode != 0:
            return False

        # Sprawdź czy są zmiany do zacommitowania
        result_status = run_cmd("git diff --cached --name-only", cwd=REPO_PATH)
        if not result_status.stdout.strip():
            print("ℹ️ Brak zmian do zacommitowania")
            return True

        # Git commit
        print("\n💾 Tworzę commit...")
        msg = f"Auto-update index.html ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})"
        result_commit = run_cmd(f'git commit -m "{msg}"', cwd=REPO_PATH)
        
        if result_commit.returncode != 0:
            return False

        # Git push
        print(f"\n🌐 Wysyłam na GitHub (branch: {BRANCH})...")
        result_push = run_cmd(f"git push origin {BRANCH}", cwd=REPO_PATH)
        
        if result_push.returncode != 0:
            return False

        print("\n🎉 Synchronizacja zakończona pomyślnie!")
        return True

    except Exception as e:
        print(f"❌ Wystąpił błąd: {e}")
        return False

def main():
    print("🛡️ SYNCHRONIZACJA RAPORTU CYBERBEZPIECZEŃSTWA Z GITHUB")
    print("=" * 60)
    print(f"📂 Katalog bazowy: {BASE_DIR}")
    print(f"📁 Katalog raportów: {REPORTS_DIR}")
    print(f"🌿 Branch: {BRANCH}")
    print("=" * 60)
    
    try:
        success = sync_index_to_github()
        
        if success:
            print("\n✅ SUKCES! Raport został zsynchronizowany z GitHub.")
        else:
            print("\n❌ BŁĄD! Synchronizacja nie powiodła się.")
            
    except KeyboardInterrupt:
        print("\n⚠️ Przerwano przez użytkownika (Ctrl+C)")
    except Exception as e:
        print(f"\n❌ Nieoczekiwany błąd: {e}")
    
    # Zatrzymaj okno - czekaj na input użytkownika
    print("\n" + "=" * 60)
    input("Naciśnij ENTER aby zamknąć okno...")

if __name__ == "__main__":
    main()