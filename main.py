
from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import sqlite3
import requests
import hashlib
import secrets
import hmac
import re
import time
from pathlib import Path
from threading import Lock

# =========================================================
# CONFIGURACAO
# =========================================================

APP_DIR = Path(__file__).resolve().parent
BANCO = APP_DIR / "astra.db"
STATIC_DIR = APP_DIR / "static"

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODELO = "qwen2.5:3b"
TEMPO_URL = "https://api.open-meteo.com/v1/forecast"

NOME_APP = "PCNOT AI"
TERMOS_VERSAO = "1.0 - 12/11/2026"

COOKIE_SESSAO = "astra_session"
DURACAO_SESSAO = 60 * 60 * 24 * 30

app = FastAPI(
    title="PCNOT AI",
    version="3.0.0",
    docs_url="/docs"
)

_RATE_LOCK = Lock()
_RATE = {}


# =========================================================
# LIMITADOR E VALIDACAO
# =========================================================

def limitar_tentativas(chave: str, limite: int, janela: int):
    agora = time.time()

    with _RATE_LOCK:
        tentativas = [
            t for t in _RATE.get(chave, [])
            if agora - t < janela
        ]

        if len(tentativas) >= limite:
            _RATE[chave] = tentativas

            raise HTTPException(
                status_code=429,
                detail="Muitas tentativas. Aguarde um pouco e tente novamente."
            )

        tentativas.append(agora)
        _RATE[chave] = tentativas


def validar_origem(request: Request):
    origem = request.headers.get("origin")

    if not origem:
        return

    host = request.headers.get("host", "").lower()

    origem_host = re.sub(
        r"^https?://", "", origem.lower()
    ).split("/")[0]

    if host and origem_host != host:
        raise HTTPException(
            status_code=403,
            detail="Origem da requisicao nao permitida."
        )


# =========================================================
# BANCO DE DADOS E MIGRACOES
# =========================================================

def conectar():
    banco = sqlite3.connect(str(BANCO), timeout=30)
    banco.row_factory = sqlite3.Row

    banco.execute("PRAGMA foreign_keys = ON")
    banco.execute("PRAGMA busy_timeout = 30000")
    banco.execute("PRAGMA journal_mode = WAL")

    banco.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            nome_exibicao TEXT NOT NULL,
            finalidade TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            admin INTEGER NOT NULL DEFAULT 0,
            ativo INTEGER NOT NULL DEFAULT 1,
            data TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # MIGRACAO DOS TERMOS
    colunas_usuarios = {
        r["name"]
        for r in banco.execute("PRAGMA table_info(usuarios)")
    }

    if "termos_versao" not in colunas_usuarios:
        banco.execute("""
            ALTER TABLE usuarios
            ADD COLUMN termos_versao TEXT
        """)

    if "termos_aceitos_em" not in colunas_usuarios:
        banco.execute("""
            ALTER TABLE usuarios
            ADD COLUMN termos_aceitos_em TEXT
        """)

    banco.execute("""
        CREATE TABLE IF NOT EXISTS sessoes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expira_em INTEGER NOT NULL,
            FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
        )
    """)

    banco.execute("""
        CREATE TABLE IF NOT EXISTS conversas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT,
            data TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    banco.execute("""
        CREATE TABLE IF NOT EXISTS mensagens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversa_id INTEGER,
            papel TEXT,
            conteudo TEXT,
            FOREIGN KEY(conversa_id) REFERENCES conversas(id)
        )
    """)

    colunas_conv = {
        r["name"]
        for r in banco.execute("PRAGMA table_info(conversas)")
    }

    if "usuario_id" not in colunas_conv:
        banco.execute(
            "ALTER TABLE conversas ADD COLUMN usuario_id INTEGER"
        )

    info_mem = banco.execute(
        "PRAGMA table_info(memorias)"
    ).fetchall()

    if not info_mem:
        banco.execute("""
            CREATE TABLE memorias (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER,
                conteudo TEXT NOT NULL,
                data TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
            )
        """)
    else:
        nomes = {r["name"] for r in info_mem}

        indices = banco.execute(
            "PRAGMA index_list(memorias)"
        ).fetchall()

        unique_global = False

        for idx in indices:
            if idx["unique"]:
                cols_idx = banco.execute(
                    f'PRAGMA index_info("{idx["name"]}")'
                ).fetchall()

                cols = [c["name"] for c in cols_idx]

                if cols == ["conteudo"]:
                    unique_global = True

        if "usuario_id" not in nomes or unique_global:
            banco.execute("""
                CREATE TABLE IF NOT EXISTS memorias_nova (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usuario_id INTEGER,
                    conteudo TEXT NOT NULL,
                    data TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
                )
            """)

            usuario_expr = (
                "usuario_id" if "usuario_id" in nomes else "NULL"
            )

            data_expr = (
                "data" if "data" in nomes else "CURRENT_TIMESTAMP"
            )

            banco.execute(f"""
                INSERT OR IGNORE INTO memorias_nova
                (id, usuario_id, conteudo, data)
                SELECT id, {usuario_expr}, conteudo, {data_expr}
                FROM memorias
            """)

            banco.execute("DROP TABLE memorias")

            banco.execute(
                "ALTER TABLE memorias_nova RENAME TO memorias"
            )

    banco.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_memoria_usuario_conteudo
        ON memorias(usuario_id, conteudo)
    """)

    banco.execute("""
        CREATE INDEX IF NOT EXISTS idx_conversas_usuario
        ON conversas(usuario_id)
    """)

    banco.execute("""
        CREATE INDEX IF NOT EXISTS idx_sessoes_token
        ON sessoes(token_hash)
    """)

    banco.execute("""
        CREATE INDEX IF NOT EXISTS idx_mensagens_conversa
        ON mensagens(conversa_id, id)
    """)

    admin_antigo = banco.execute("""
        SELECT id FROM usuarios
        WHERE admin = 1
        ORDER BY id LIMIT 1
    """).fetchone()

    if admin_antigo:
        banco.execute("""
            UPDATE conversas
            SET usuario_id = ?
            WHERE usuario_id IS NULL
        """, (admin_antigo["id"],))

        banco.execute("""
            UPDATE memorias
            SET usuario_id = ?
            WHERE usuario_id IS NULL
        """, (admin_antigo["id"],))

    banco.execute(
        "DELETE FROM sessoes WHERE expira_em <= ?",
        (int(time.time()),)
    )

    banco.commit()
    return banco


conectar().close()


# =========================================================
# SENHAS E SESSOES
# =========================================================

def gerar_hash_senha(senha: str) -> str:
    sal = secrets.token_bytes(16)

    resultado = hashlib.scrypt(
        senha.encode("utf-8"),
        salt=sal,
        n=2**14,
        r=8,
        p=1,
        dklen=64
    )

    return sal.hex() + ":" + resultado.hex()


def verificar_senha(senha: str, senha_hash: str) -> bool:
    try:
        sal_hex, hash_original = senha_hash.split(":")

        resultado = hashlib.scrypt(
            senha.encode("utf-8"),
            salt=bytes.fromhex(sal_hex),
            n=2**14,
            r=8,
            p=1,
            dklen=64
        )

        return hmac.compare_digest(
            resultado.hex(), hash_original
        )

    except (ValueError, TypeError):
        return False


def criar_sessao(
    banco,
    usuario_id: int,
    response: Response,
    request: Request
):
    token = secrets.token_urlsafe(48)

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    expira = int(time.time()) + DURACAO_SESSAO

    banco.execute("""
        INSERT INTO sessoes
        (usuario_id, token_hash, expira_em)
        VALUES (?, ?, ?)
    """, (usuario_id, token_hash, expira))

    https = (
        request.url.scheme == "https"
        or request.headers.get(
            "x-forwarded-proto", ""
        ).lower() == "https"
    )

    response.set_cookie(
        key=COOKIE_SESSAO,
        value=token,
        httponly=True,
        secure=https,
        samesite="lax",
        max_age=DURACAO_SESSAO,
        path="/"
    )


def usuario_atual(request: Request):
    token = request.cookies.get(COOKIE_SESSAO)

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Faça login para continuar."
        )

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    banco = conectar()

    try:
        dados = banco.execute("""
            SELECT
                u.id,
                u.username,
                u.nome_exibicao,
                u.finalidade,
                u.admin,
                u.ativo
            FROM sessoes s
            JOIN usuarios u ON u.id = s.usuario_id
            WHERE s.token_hash = ? AND s.expira_em > ?
        """, (token_hash, int(time.time()))).fetchone()

        if not dados or not dados["ativo"]:
            raise HTTPException(
                status_code=401,
                detail="Sessão inválida ou conta bloqueada."
            )

        return {
            "id": dados["id"],
            "username": dados["username"],
            "nome_exibicao": dados["nome_exibicao"],
            "finalidade": dados["finalidade"],
            "admin": bool(dados["admin"])
        }

    finally:
        banco.close()


def exigir_admin(usuario=Depends(usuario_atual)):
    if not usuario["admin"]:
        raise HTTPException(
            status_code=403,
            detail="Acesso permitido somente ao administrador."
        )

    return usuario


# =========================================================
# MODELOS
# =========================================================

class Cadastro(BaseModel):
    username: str = Field(min_length=3, max_length=24)
    nome_exibicao: str = Field(min_length=2, max_length=40)
    finalidade: str = Field(min_length=5, max_length=300)
    senha: str = Field(min_length=8, max_length=128)
    aceitou_termos: bool


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=24)
    senha: str = Field(min_length=1, max_length=128)


class StatusUsuario(BaseModel):
    ativo: bool


class Mensagem(BaseModel):
    texto: str = Field(min_length=1, max_length=12000)
    conversa_id: int | None = None


# =========================================================
# ARQUIVOS E STATUS
# =========================================================

app.mount(
    "/static",
    StaticFiles(directory=str(STATIC_DIR)),
    name="static"
)


@app.get("/")
def inicio():
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/termos")
def pagina_termos():
    return FileResponse(str(STATIC_DIR / "termos.html"))


@app.get("/status")
def status():
    return {
        "nome": NOME_APP,
        "status": "online",
        "modelo": MODELO
    }


# =========================================================
# CADASTRO / LOGIN / LOGOUT
# =========================================================

@app.post("/auth/register")
def cadastrar(
    dados: Cadastro,
    request: Request,
    response: Response
):
    validar_origem(request)

    ip = request.client.host if request.client else "local"

    limitar_tentativas(
        "register:" + ip,
        8,
        3600
    )

    username = dados.username.strip().lower()
    nome = dados.nome_exibicao.strip()
    finalidade = dados.finalidade.strip()
    senha = dados.senha

    if dados.aceitou_termos is not True:
        raise HTTPException(
            status_code=400,
            detail="Você precisa aceitar os Termos de Uso e a Política de Privacidade."
        )

    if not re.fullmatch(r"[a-z0-9_.-]{3,24}", username):
        raise HTTPException(
            status_code=400,
            detail="O usuário deve ter de 3 a 24 caracteres: letras, números, ponto, hífen ou underline."
        )

    if len(nome) < 2:
        raise HTTPException(
            status_code=400,
            detail="Informe um nome com pelo menos 2 caracteres."
        )

    if len(finalidade) < 5:
        raise HTTPException(
            status_code=400,
            detail="Informe como pretende utilizar a PCNOT AI."
        )

    banco = conectar()

    try:
        banco.execute("BEGIN IMMEDIATE")

        quantidade = banco.execute("""
            SELECT COUNT(*) AS total FROM usuarios
        """).fetchone()["total"]

        # A primeira conta de uma base vazia vira administradora.
        admin = 1 if quantidade == 0 else 0

        cursor = banco.execute("""
            INSERT INTO usuarios
            (
                username,
                nome_exibicao,
                finalidade,
                password_hash,
                admin,
                termos_versao,
                termos_aceitos_em
            )
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            username,
            nome,
            finalidade,
            gerar_hash_senha(senha),
            admin,
            TERMOS_VERSAO
        ))

        usuario_id = cursor.lastrowid

        if admin:
            banco.execute("""
                UPDATE conversas
                SET usuario_id = ?
                WHERE usuario_id IS NULL
            """, (usuario_id,))

            banco.execute("""
                UPDATE memorias
                SET usuario_id = ?
                WHERE usuario_id IS NULL
            """, (usuario_id,))

        criar_sessao(
            banco,
            usuario_id,
            response,
            request
        )

        banco.commit()

        return {
            "sucesso": True,
            "usuario": {
                "id": usuario_id,
                "username": username,
                "nome_exibicao": nome,
                "finalidade": finalidade,
                "admin": bool(admin)
            }
        }

    except sqlite3.IntegrityError:
        banco.rollback()

        raise HTTPException(
            status_code=409,
            detail="Esse nome de usuário já está cadastrado."
        )

    finally:
        banco.close()


@app.post("/auth/login")
def login(
    dados: Login,
    request: Request,
    response: Response
):
    validar_origem(request)

    ip = request.client.host if request.client else "local"

    limitar_tentativas(
        "login:" + ip,
        12,
        300
    )

    banco = conectar()

    try:
        usuario = banco.execute("""
            SELECT
                id,
                username,
                nome_exibicao,
                finalidade,
                password_hash,
                admin,
                ativo
            FROM usuarios
            WHERE username = ?
        """, (
            dados.username.strip().lower(),
        )).fetchone()

        if not usuario or not verificar_senha(
            dados.senha,
            usuario["password_hash"]
        ):
            raise HTTPException(
                status_code=401,
                detail="Usuário ou senha incorretos."
            )

        if not usuario["ativo"]:
            raise HTTPException(
                status_code=403,
                detail="Sua conta está bloqueada."
            )

        criar_sessao(
            banco,
            usuario["id"],
            response,
            request
        )

        banco.commit()

        return {
            "sucesso": True,
            "usuario": {
                "id": usuario["id"],
                "username": usuario["username"],
                "nome_exibicao": usuario["nome_exibicao"],
                "finalidade": usuario["finalidade"],
                "admin": bool(usuario["admin"])
            }
        }

    finally:
        banco.close()


@app.get("/auth/me")
def minha_conta(usuario=Depends(usuario_atual)):
    return {"usuario": usuario}


@app.post("/auth/logout")
def logout(
    request: Request,
    response: Response,
    usuario=Depends(usuario_atual)
):
    validar_origem(request)

    token = request.cookies.get(COOKIE_SESSAO)

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    banco = conectar()

    try:
        banco.execute(
            "DELETE FROM sessoes WHERE token_hash = ?",
            (token_hash,)
        )

        banco.commit()

    finally:
        banco.close()

    response.delete_cookie(
        COOKIE_SESSAO,
        path="/",
        httponly=True,
        samesite="lax",
        secure=(
            request.url.scheme == "https"
            or request.headers.get(
                "x-forwarded-proto", ""
            ).lower() == "https"
        )
    )

    return {"sucesso": True}


# =========================================================
# ADMIN: USUARIOS
# =========================================================

@app.get("/admin/usuarios")
def listar_usuarios(admin=Depends(exigir_admin)):
    banco = conectar()

    try:
        dados = banco.execute("""
            SELECT
                id,
                username,
                nome_exibicao,
                finalidade,
                admin,
                ativo,
                data,
                termos_versao,
                termos_aceitos_em
            FROM usuarios
            ORDER BY id
        """).fetchall()

        return {
            "usuarios": [
                {
                    "id": r["id"],
                    "username": r["username"],
                    "nome_exibicao": r["nome_exibicao"],
                    "finalidade": r["finalidade"],
                    "admin": bool(r["admin"]),
                    "ativo": bool(r["ativo"]),
                    "data": r["data"],
                    "termos_versao": r["termos_versao"],
                    "termos_aceitos_em": r["termos_aceitos_em"]
                }
                for r in dados
            ]
        }

    finally:
        banco.close()


@app.patch("/admin/usuarios/{usuario_id}/status")
def alterar_status(
    usuario_id: int,
    dados: StatusUsuario,
    request: Request,
    admin=Depends(exigir_admin)
):
    validar_origem(request)

    if usuario_id == admin["id"]:
        raise HTTPException(
            status_code=400,
            detail="Você não pode bloquear sua própria conta."
        )

    banco = conectar()

    try:
        alvo = banco.execute("""
            SELECT id, admin
            FROM usuarios
            WHERE id = ?
        """, (usuario_id,)).fetchone()

        if not alvo:
            raise HTTPException(
                status_code=404,
                detail="Usuário não encontrado."
            )

        if alvo["admin"]:
            raise HTTPException(
                status_code=403,
                detail="Não é permitido bloquear outra conta administradora."
            )

        banco.execute("""
            UPDATE usuarios
            SET ativo = ?
            WHERE id = ?
        """, (
            int(dados.ativo),
            usuario_id
        ))

        if not dados.ativo:
            banco.execute("""
                DELETE FROM sessoes
                WHERE usuario_id = ?
            """, (usuario_id,))

        banco.commit()

        return {"sucesso": True}

    finally:
        banco.close()


# =========================================================
# ADMIN: TODAS AS CONVERSAS
# =========================================================

@app.get("/admin/conversas")
def admin_listar_conversas(admin=Depends(exigir_admin)):
    banco = conectar()

    try:
        dados = banco.execute("""
            SELECT
                c.id,
                c.titulo,
                c.data,
                u.username,
                u.nome_exibicao
            FROM conversas c
            LEFT JOIN usuarios u ON u.id = c.usuario_id
            ORDER BY c.id DESC
        """).fetchall()

        return {
            "conversas": [
                {
                    "id": r["id"],
                    "titulo": r["titulo"] or "Nova conversa",
                    "data": r["data"],
                    "username": r["username"] or "conta antiga",
                    "nome_exibicao": (
                        r["nome_exibicao"] or "Usuário antigo"
                    )
                }
                for r in dados
            ]
        }

    finally:
        banco.close()


@app.get("/admin/conversas/{conversa_id}")
def admin_abrir_conversa(
    conversa_id: int,
    admin=Depends(exigir_admin)
):
    banco = conectar()

    try:
        conversa = banco.execute("""
            SELECT
                c.id,
                c.titulo,
                c.data,
                u.username,
                u.nome_exibicao
            FROM conversas c
            LEFT JOIN usuarios u ON u.id = c.usuario_id
            WHERE c.id = ?
        """, (conversa_id,)).fetchone()

        if not conversa:
            raise HTTPException(
                status_code=404,
                detail="Conversa não encontrada."
            )

        mensagens = banco.execute("""
            SELECT papel, conteudo
            FROM mensagens
            WHERE conversa_id = ?
            ORDER BY id
        """, (conversa_id,)).fetchall()

        return {
            "conversa": {
                "id": conversa["id"],
                "titulo": conversa["titulo"] or "Nova conversa",
                "data": conversa["data"],
                "username": conversa["username"] or "conta antiga",
                "nome_exibicao": (
                    conversa["nome_exibicao"] or "Usuário antigo"
                )
            },
            "mensagens": [
                {
                    "role": m["papel"],
                    "content": m["conteudo"]
                }
                for m in mensagens
            ]
        }

    finally:
        banco.close()


# =========================================================
# CONVERSAS INDIVIDUAIS
# =========================================================

@app.get("/conversas")
def listar_conversas(usuario=Depends(usuario_atual)):
    banco = conectar()

    try:
        dados = banco.execute("""
            SELECT id, titulo, data
            FROM conversas
            WHERE usuario_id = ?
            ORDER BY id DESC
        """, (usuario["id"],)).fetchall()

        return [
            {
                "id": r["id"],
                "titulo": r["titulo"],
                "data": r["data"]
            }
            for r in dados
        ]

    finally:
        banco.close()


@app.get("/conversas/{conversa_id}")
def abrir_conversa(
    conversa_id: int,
    usuario=Depends(usuario_atual)
):
    banco = conectar()

    try:
        existe = banco.execute("""
            SELECT id
            FROM conversas
            WHERE id = ? AND usuario_id = ?
        """, (
            conversa_id,
            usuario["id"]
        )).fetchone()

        if not existe:
            raise HTTPException(
                status_code=404,
                detail="Conversa não encontrada."
            )

        dados = banco.execute("""
            SELECT papel, conteudo
            FROM mensagens
            WHERE conversa_id = ?
            ORDER BY id
        """, (conversa_id,)).fetchall()

        return [
            {
                "role": r["papel"],
                "content": r["conteudo"]
            }
            for r in dados
        ]

    finally:
        banco.close()


@app.delete("/conversas/{conversa_id}")
def excluir_conversa(
    conversa_id: int,
    request: Request,
    usuario=Depends(usuario_atual)
):
    validar_origem(request)

    banco = conectar()

    try:
        existe = banco.execute("""
            SELECT id
            FROM conversas
            WHERE id = ? AND usuario_id = ?
        """, (
            conversa_id,
            usuario["id"]
        )).fetchone()

        if not existe:
            raise HTTPException(
                status_code=404,
                detail="Conversa não encontrada."
            )

        banco.execute("""
            DELETE FROM mensagens
            WHERE conversa_id = ?
        """, (conversa_id,))

        banco.execute("""
            DELETE FROM conversas
            WHERE id = ? AND usuario_id = ?
        """, (
            conversa_id,
            usuario["id"]
        ))

        banco.commit()

        return {"sucesso": True}

    finally:
        banco.close()


# =========================================================
# MEMORIAS INDIVIDUAIS
# =========================================================

def salvar_memoria(texto: str, usuario_id: int, banco):
    comandos = (
        "lembre-se:",
        "lembre que:",
        "guarde que:",
        "memorize:"
    )

    limpo = texto.strip()

    for comando in comandos:
        if limpo.lower().startswith(comando):
            memoria = limpo[len(comando):].strip()

            if memoria:
                banco.execute("""
                    INSERT OR IGNORE INTO memorias
                    (usuario_id, conteudo)
                    VALUES (?, ?)
                """, (
                    usuario_id,
                    memoria
                ))

                return memoria

    return None


def carregar_memorias(usuario_id: int):
    banco = conectar()

    try:
        dados = banco.execute("""
            SELECT conteudo
            FROM memorias
            WHERE usuario_id = ?
            ORDER BY id DESC
            LIMIT 50
        """, (usuario_id,)).fetchall()

        return [r["conteudo"] for r in dados]

    finally:
        banco.close()


@app.get("/memorias")
def listar_memorias(usuario=Depends(usuario_atual)):
    banco = conectar()

    try:
        dados = banco.execute("""
            SELECT id, conteudo, data
            FROM memorias
            WHERE usuario_id = ?
            ORDER BY id DESC
        """, (usuario["id"],)).fetchall()

        return {
            "memorias": [
                {
                    "id": r["id"],
                    "conteudo": r["conteudo"],
                    "data": r["data"]
                }
                for r in dados
            ]
        }

    finally:
        banco.close()


@app.delete("/memorias/{memoria_id}")
def excluir_memoria(
    memoria_id: int,
    request: Request,
    usuario=Depends(usuario_atual)
):
    validar_origem(request)

    banco = conectar()

    try:
        banco.execute("""
            DELETE FROM memorias
            WHERE id = ? AND usuario_id = ?
        """, (
            memoria_id,
            usuario["id"]
        ))

        banco.commit()

        return {"sucesso": True}

    finally:
        banco.close()


# =========================================================
# CLIMA
# =========================================================

CIDADES = {
    "belo horizonte": (-19.9167, -43.9345),
    "são paulo": (-23.5505, -46.6333),
    "rio de janeiro": (-22.9068, -43.1729),
    "brasília": (-15.7939, -47.8828),
    "curitiba": (-25.4284, -49.2733),
    "salvador": (-12.9777, -38.5016),
    "fortaleza": (-3.7319, -38.5267),
    "recife": (-8.0476, -34.8770)
}


def consultar_clima(cidade="Belo Horizonte"):
    chave = cidade.strip().lower()

    if chave not in CIDADES:
        return f"Não tenho coordenadas cadastradas para {cidade}."

    lat, lon = CIDADES[chave]

    parametros = {
        "latitude": lat,
        "longitude": lon,
        "current": [
            "temperature_2m",
            "apparent_temperature",
            "relative_humidity_2m",
            "wind_speed_10m",
            "precipitation"
        ],
        "daily": [
            "temperature_2m_max",
            "temperature_2m_min",
            "precipitation_probability_max"
        ],
        "forecast_days": 2,
        "timezone": "America/Sao_Paulo"
    }

    resposta = requests.get(
        TEMPO_URL,
        params=parametros,
        timeout=15
    )

    resposta.raise_for_status()

    dados = resposta.json()

    atual = dados["current"]
    previsao = dados["daily"]

    return f"""
DADOS DO CLIMA EM {cidade.upper()}:

Temperatura atual: {atual['temperature_2m']}°C
Sensação térmica: {atual['apparent_temperature']}°C
Umidade: {atual['relative_humidity_2m']}%
Vento: {atual['wind_speed_10m']} km/h
Precipitação atual: {atual['precipitation']} mm

Hoje:
Máxima: {previsao['temperature_2m_max'][0]}°C
Mínima: {previsao['temperature_2m_min'][0]}°C
Probabilidade máxima de chuva: {previsao['precipitation_probability_max'][0]}%

Amanhã:
Máxima: {previsao['temperature_2m_max'][1]}°C
Mínima: {previsao['temperature_2m_min'][1]}°C
Probabilidade máxima de chuva: {previsao['precipitation_probability_max'][1]}%

Fonte: Open-Meteo.
"""


def identificar_pergunta_clima(texto):
    termos = [
        "clima",
        "temperatura",
        "quantos graus",
        "previsão do tempo",
        "vai chover",
        "tempo amanhã",
        "sensação térmica",
        "umidade do ar"
    ]

    t = texto.lower()

    return any(p in t for p in termos)


def identificar_cidade(texto):
    t = texto.lower()

    for cidade in CIDADES:
        if cidade in t:
            return cidade

    return "Belo Horizonte"


# =========================================================
# PERSONALIDADE E MOTOR LOCAL
# =========================================================

def criar_sistema(usuario_id):
    memorias = carregar_memorias(usuario_id)

    texto_memorias = "\n".join(
        "- " + m for m in memorias
    )

    return f"""
Você é PCNOT AI, uma assistente pessoal de inteligência artificial.

Converse em português brasileiro, com clareza, educação e naturalidade.
Seu nome é PCNOT AI. Não diga que seu nome é ASTRA ou qualquer outro nome.
Seja prestativa, contextual e evite repetir informações.
Ajude com estudos, tecnologia, programação, matemática e assuntos gerais.
Quando escrever código, respeite o contexto e explique como executar.
Não invente notícias, datas, preços, clima ou acontecimentos atuais.
Se não souber algo, admita a limitação.
Use as memórias abaixo apenas quando forem relevantes.
Não invente dados pessoais.

MEMÓRIAS DO USUÁRIO:
{texto_memorias}
"""


def gerar_resposta(prompt, sistema):
    resposta = requests.post(
        OLLAMA_URL,
        json={
            "model": MODELO,
            "system": sistema,
            "prompt": prompt,
            "stream": False,
            "keep_alive": "10m",
            "options": {
                "temperature": 0.5,
                "num_predict": 600,
                "num_ctx": 4096,
                "top_p": 0.9
            }
        },
        timeout=180
    )

    resposta.raise_for_status()

    texto = resposta.json().get(
        "response", ""
    ).strip()

    if not texto:
        raise ValueError(
            "O modelo não retornou uma resposta."
        )

    return texto


# =========================================================
# CONVERSAR
# =========================================================

@app.post("/conversar")
def conversar(
    mensagem: Mensagem,
    request: Request,
    usuario=Depends(usuario_atual)
):
    validar_origem(request)

    texto_usuario = mensagem.texto.strip()

    if not texto_usuario:
        raise HTTPException(
            status_code=400,
            detail="Digite uma mensagem."
        )

    banco = conectar()

    conversa_id = mensagem.conversa_id

    try:
        if conversa_id is not None:
            existe = banco.execute("""
                SELECT id
                FROM conversas
                WHERE id = ? AND usuario_id = ?
            """, (
                conversa_id,
                usuario["id"]
            )).fetchone()

            if not existe:
                raise HTTPException(
                    status_code=404,
                    detail="Conversa não encontrada."
                )

        else:
            cursor = banco.execute("""
                INSERT INTO conversas
                (titulo, usuario_id)
                VALUES (?, ?)
            """, (
                texto_usuario[:60],
                usuario["id"]
            ))

            conversa_id = cursor.lastrowid

        memoria_salva = salvar_memoria(
            texto_usuario,
            usuario["id"],
            banco
        )

        banco.execute("""
            INSERT INTO mensagens
            (conversa_id, papel, conteudo)
            VALUES (?, 'user', ?)
        """, (
            conversa_id,
            texto_usuario
        ))

        banco.commit()

        historico = banco.execute("""
            SELECT m.papel, m.conteudo
            FROM mensagens m
            JOIN conversas c ON c.id = m.conversa_id
            WHERE c.id = ? AND c.usuario_id = ?
            ORDER BY m.id DESC
            LIMIT 20
        """, (
            conversa_id,
            usuario["id"]
        )).fetchall()

        historico.reverse()

        contexto = "\n".join(
            (
                "Usuário"
                if r["papel"] == "user"
                else "PCNOT AI"
            ) + ": " + r["conteudo"]
            for r in historico
        )

        sistema = criar_sistema(usuario["id"])

        if identificar_pergunta_clima(texto_usuario):
            cidade = identificar_cidade(texto_usuario)

            try:
                clima = consultar_clima(cidade)

                prompt = (
                    f"Histórico:\n{contexto}\n\n"
                    f"Pergunta atual: {texto_usuario}\n\n"
                    f"Use estes dados sem alterar valores:\n{clima}\n"
                    "Responda em português brasileiro."
                )

            except requests.RequestException:
                prompt = (
                    f"Histórico:\n{contexto}\n\n"
                    f"Pergunta: {texto_usuario}\n"
                    "A consulta meteorológica falhou. "
                    "Informe que não foi possível obter os dados atuais. "
                    "Não invente temperatura nem previsão."
                )

        else:
            prompt = (
                "/no_think\n"
                "Continue a conversa respondendo somente como PCNOT AI.\n\n"
                + contexto
                + "\nPCNOT AI:"
            )

        texto_resposta = gerar_resposta(
            prompt,
            sistema
        )

        banco.execute("""
            INSERT INTO mensagens
            (conversa_id, papel, conteudo)
            VALUES (?, 'assistant', ?)
        """, (
            conversa_id,
            texto_resposta
        ))

        banco.commit()

        return {
            "resposta": texto_resposta,
            "conversa_id": conversa_id,
            "memoria_salva": memoria_salva is not None
        }

    except HTTPException:
        raise

    except requests.RequestException as erro:
        print(
            "Falha ao acessar Ollama/serviço externo:",
            erro
        )

        return {
            "resposta": (
                "Não consegui acessar um serviço necessário. "
                "Confira se o Ollama está aberto e se o modelo está instalado."
            ),
            "conversa_id": conversa_id
        }

    except Exception as erro:
        print(
            "Erro interno ao conversar:",
            repr(erro)
        )

        return {
            "resposta": (
                "Ocorreu um erro interno ao processar sua mensagem. "
                "Confira o terminal do servidor."
            ),
            "conversa_id": conversa_id
        }

    finally:
        banco.close()
