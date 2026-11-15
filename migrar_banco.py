
import sqlite3
import getpass
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg.rows import dict_row


PASTA = Path(__file__).resolve().parent
BANCO_ANTIGO = PASTA / "astra.db"


def data_segura(valor):
    if not valor:
        return None

    try:
        if isinstance(valor, (int, float)):
            return datetime.fromtimestamp(valor, timezone.utc)

        texto = str(valor).strip().replace("Z", "+00:00")
        resultado = datetime.fromisoformat(texto)

        if resultado.tzinfo is None:
            resultado = resultado.replace(tzinfo=timezone.utc)

        return resultado

    except (ValueError, TypeError, OverflowError):
        return None


def migrar():
    if not BANCO_ANTIGO.exists():
        print("ERRO: astra.db não encontrado.")
        return

    print("PCNOT AI - MIGRAÇÃO DO BANCO")
    print("Digite a conexão do Supabase. A senha ficará oculta.")
    database_url = getpass.getpass("DATABASE_URL: ").strip()

    if not database_url:
        print("Conexão não informada.")
        return

    origem = sqlite3.connect(BANCO_ANTIGO)
    origem.row_factory = sqlite3.Row

    try:
        with psycopg.connect(
            database_url,
            row_factory=dict_row,
            connect_timeout=20
        ) as destino:

            with destino.cursor() as cursor:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS usuarios (
                        id BIGINT PRIMARY KEY,
                        username TEXT NOT NULL,
                        nome_exibicao TEXT NOT NULL,
                        finalidade TEXT DEFAULT '',
                        password_hash TEXT NOT NULL,
                        admin BOOLEAN DEFAULT FALSE,
                        ativo BOOLEAN DEFAULT TRUE,
                        criado_em TIMESTAMPTZ DEFAULT NOW(),
                        termos_versao TEXT,
                        termos_aceitos_em TIMESTAMPTZ
                    )
                """)

                cursor.execute("""
                    ALTER TABLE usuarios
                    ADD COLUMN IF NOT EXISTS termos_versao TEXT
                """)
                cursor.execute("""
                    ALTER TABLE usuarios
                    ADD COLUMN IF NOT EXISTS termos_aceitos_em TIMESTAMPTZ
                """)

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS sessoes (
                        id BIGINT PRIMARY KEY,
                        usuario_id BIGINT NOT NULL REFERENCES usuarios(id)
                            ON DELETE CASCADE,
                        token_hash TEXT NOT NULL UNIQUE,
                        expira_em TIMESTAMPTZ NOT NULL,
                        criado_em TIMESTAMPTZ DEFAULT NOW()
                    )
                """)

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS conversas (
                        id BIGINT PRIMARY KEY,
                        usuario_id BIGINT NOT NULL REFERENCES usuarios(id)
                            ON DELETE CASCADE,
                        titulo TEXT DEFAULT 'Nova conversa',
                        criada_em TIMESTAMPTZ DEFAULT NOW(),
                        atualizada_em TIMESTAMPTZ DEFAULT NOW()
                    )
                """)

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS mensagens (
                        id BIGINT PRIMARY KEY,
                        conversa_id BIGINT NOT NULL REFERENCES conversas(id)
                            ON DELETE CASCADE,
                        usuario_id BIGINT NOT NULL REFERENCES usuarios(id)
                            ON DELETE CASCADE,
                        papel TEXT NOT NULL,
                        conteudo TEXT NOT NULL,
                        criada_em TIMESTAMPTZ DEFAULT NOW()
                    )
                """)

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS memorias (
                        id BIGINT PRIMARY KEY,
                        usuario_id BIGINT NOT NULL REFERENCES usuarios(id)
                            ON DELETE CASCADE,
                        conteudo TEXT NOT NULL,
                        criada_em TIMESTAMPTZ DEFAULT NOW()
                    )
                """)

                cursor.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS usuarios_username_unico
                    ON usuarios (LOWER(username))
                """)

                cursor.execute("""
                    SELECT
                        (SELECT COUNT(*) FROM usuarios) AS usuarios,
                        (SELECT COUNT(*) FROM sessoes) AS sessoes,
                        (SELECT COUNT(*) FROM conversas) AS conversas,
                        (SELECT COUNT(*) FROM mensagens) AS mensagens,
                        (SELECT COUNT(*) FROM memorias) AS memorias
                """)

                totais = cursor.fetchone()

                if any(totais.values()):
                    raise RuntimeError(
                        "O Supabase já contém dados. Migração cancelada "
                        "para evitar misturar ou duplicar registros."
                    )

                usuarios = origem.execute(
                    "SELECT * FROM usuarios ORDER BY id"
                ).fetchall()

                for u in usuarios:
                    cursor.execute("""
                        INSERT INTO usuarios (
                            id, username, nome_exibicao, finalidade,
                            password_hash, admin, ativo, criado_em,
                            termos_versao, termos_aceitos_em
                        )
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """, (
                        u["id"],
                        u["username"],
                        u["nome_exibicao"],
                        u["finalidade"] or "",
                        u["password_hash"],
                        bool(u["admin"]),
                        bool(u["ativo"]),
                        data_segura(u["data"]) or datetime.now(timezone.utc),
                        u["termos_versao"],
                        data_segura(u["termos_aceitos_em"])
                    ))

                conversas = origem.execute(
                    "SELECT * FROM conversas ORDER BY id"
                ).fetchall()

                for c in conversas:
                    data = data_segura(c["data"]) or datetime.now(timezone.utc)

                    cursor.execute("""
                        INSERT INTO conversas (
                            id, usuario_id, titulo, criada_em, atualizada_em
                        )
                        VALUES (%s,%s,%s,%s,%s)
                    """, (
                        c["id"],
                        c["usuario_id"],
                        c["titulo"] or "Nova conversa",
                        data,
                        data
                    ))

                sessoes = origem.execute(
                    "SELECT * FROM sessoes ORDER BY id"
                ).fetchall()

                for s in sessoes:
                    cursor.execute("""
                        INSERT INTO sessoes (
                            id, usuario_id, token_hash, expira_em
                        )
                        VALUES (%s,%s,%s,%s)
                    """, (
                        s["id"],
                        s["usuario_id"],
                        s["token_hash"],
                        data_segura(s["expira_em"])
                    ))

                mensagens = origem.execute("""
                    SELECT m.id, m.conversa_id, m.papel, m.conteudo,
                           c.usuario_id
                    FROM mensagens m
                    JOIN conversas c ON c.id = m.conversa_id
                    ORDER BY m.id
                """).fetchall()

                for m in mensagens:
                    cursor.execute("""
                        INSERT INTO mensagens (
                            id, conversa_id, usuario_id, papel, conteudo
                        )
                        VALUES (%s,%s,%s,%s,%s)
                    """, (
                        m["id"],
                        m["conversa_id"],
                        m["usuario_id"],
                        m["papel"],
                        m["conteudo"]
                    ))

                memorias = origem.execute(
                    "SELECT * FROM memorias ORDER BY id"
                ).fetchall()

                for m in memorias:
                    cursor.execute("""
                        INSERT INTO memorias (
                            id, usuario_id, conteudo, criada_em
                        )
                        VALUES (%s,%s,%s,%s)
                    """, (
                        m["id"],
                        m["usuario_id"],
                        m["conteudo"],
                        data_segura(m["data"]) or datetime.now(timezone.utc)
                    ))

                for tabela in (
                    "usuarios", "sessoes", "conversas",
                    "mensagens", "memorias"
                ):
                    cursor.execute(f"""
                        SELECT setval(
                            pg_get_serial_sequence('{tabela}', 'id'),
                            COALESCE(MAX(id), 1),
                            MAX(id) IS NOT NULL
                        )
                        FROM {tabela}
                    """)

            print("\nMIGRAÇÃO CONCLUÍDA!")
            print("Usuários:", len(usuarios))
            print("Conversas:", len(conversas))
            print("Mensagens:", len(mensagens))
            print("Memórias:", len(memorias))
            print("Sessões:", len(sessoes))

    finally:
        origem.close()


if __name__ == "__main__":
    try:
        migrar()
    except Exception as erro:
        print("\nMIGRAÇÃO NÃO CONCLUÍDA:")
        print(str(erro))
        print("Nenhum dado do astra.db foi apagado.")
