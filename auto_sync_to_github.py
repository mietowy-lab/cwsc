import subprocess

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
    return result.returncode

def main():
    # Dodaj wszystkie zmiany
    print("Dodawanie zmian do repozytorium...")
    run_cmd("git add .")

    # Pobierz opis zmian od użytkownika
    commit_message = input("Podaj opis zmian (commit message): ")

    # Utwórz commit
    print("Tworzenie commita...")
    run_cmd(f'git commit -m "{commit_message}"')

    # Wyślij zmiany na GitHub
    print("Wysyłanie zmian na GitHub...")
    run_cmd("git push origin main")  # Zmień 'main' jeśli gałąź nazywa się inaczej

    print("Aktualizacja zakończona!")

if __name__ == "__main__":
    main()