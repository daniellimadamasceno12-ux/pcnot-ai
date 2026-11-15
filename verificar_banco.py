import sqlite3

banco = sqlite3.connect("astra.db")
cursor = banco.cursor()

tabelas = ["usuarios", "sessoes", "conversas", "mensagens", "memorias"]

for tabela in tabelas:
    print("\n====================")
    print("TABELA:", tabela)
    print("====================")

    cursor.execute(f'PRAGMA table_info("{tabela}")')

    for coluna in cursor.fetchall():
        print(coluna[1], "|", coluna[2])

banco.close()
print("\nCONFERENCIA FINALIZADA!")
