from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

import os
import re
import time
import hmac
import hashlib
import secrets
import requests
import psycopg
import base64
import binascii

from psycopg.rows import dict_row
from pathlib import Path
from threading import Lock
from contextlib import asynccontextmanager


# =========================================================
# CONFIGURAÇÕES
# =========================================================

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"

DATABASE_URL = os.getenv("DATABASE_URL")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

MODELO = "openai/gpt-oss-20b"
MODELO_VISAO = "qwen/qwen3.8-27b"

TEMPO_URL = "https://api.open-meteo.com/v1/forecast"

NOME_APP = "PCNOT AI"
VERSAO = "5.0.0"
TERMOS_VERSAO = "1.0"

TAMANHO_MAXIMO_IMAGEM = 5 * 1024 * 1024

TIPOS_IMAGEM = {
    "image/jpeg",
    "image/png",
    "image/webp"
}

if not DATABASE_URL:
    raise RuntimeError("A variável DATABASE_URL não foi configurada.")

if not GROQ_API_KEY:
    raise RuntimeError("A variável GROQ_API_KEY não foi configurada.")


# =========================================================
# CONTROLE DE REQUISIÇÕES
# =========================================================

_RATE_LOCK = Lock()
_RATE = {}

LIMITE_REQUISICOES = 30
JANELA_REQUISICOES = 60


def limitar_requisicoes(chave):
    agora = time.time()

    with _RATE_LOCK:
        historico = _RATE.get(chave, [])

        historico = [
            instante for instante in historico
            if agora - instante < JANELA_REQUISICOES
        ]

        if len(historico) >= LIMITE_REQUISICOES:
            raise HTTPException(
                status_code=429,
                detail="Muitas requisições. Aguarde um pouco."
            )

        historico.append(agora)
        _RATE[chave] = historico


# =========================================================
# CONEXÃO COM SUPABASE / POSTGRESQL
# =========================================================

def conectar():
    try:
        return psycopg.connect(
            DATABASE_URL,
            row_factory=dict_row,
            connect_timeout=15
        )

    except Exception as erro:
        print("Erro ao conectar ao Supabase:", erro)

        raise HTTPException(
            status_code=503,
            detail="Não foi possível conectar ao banco de dados."
        )


def inicializar_banco():
    comandos = [
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id BIGSERIAL PRIMARY KEY,
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
        """,

        """
        ALTER TABLE usuarios
        ADD COLUMN IF NOT EXISTS termos_versao TEXT
        """,

        """
        ALTER TABLE usuarios
        ADD COLUMN IF NOT EXISTS termos_aceitos_em TIMESTAMPTZ
        """,

        """
        CREATE UNIQUE INDEX IF NOT EXISTS usuarios_username_unico
        ON usuarios (LOWER(username))
        """,

        """
        CREATE TABLE IF NOT EXISTS sessoes (
            id BIGSERIAL PRIMARY KEY,
            usuario_id BIGINT NOT NULL REFERENCES usuarios(id)
                ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            expira_em TIMESTAMPTZ NOT NULL,
            criado_em TIMESTAMPTZ DEFAULT NOW()
        )
        """,

        """
        CREATE TABLE IF NOT EXISTS conversas (
            id BIGSERIAL PRIMARY KEY,
            usuario_id BIGINT NOT NULL REFERENCES usuarios(id)
                ON DELETE CASCADE,
            titulo TEXT DEFAULT 'Nova conversa',
            criada_em TIMESTAMPTZ DEFAULT NOW(),
            atualizada_em TIMESTAMPTZ DEFAULT NOW()
        )
        """,

        """
        CREATE TABLE IF NOT EXISTS mensagens (
            id BIGSERIAL PRIMARY KEY,
            conversa_id BIGINT NOT NULL REFERENCES conversas(id)
                ON DELETE CASCADE,
            usuario_id BIGINT NOT NULL REFERENCES usuarios(id)
                ON DELETE CASCADE,
            papel TEXT NOT NULL,
            conteudo TEXT NOT NULL,
            criada_em TIMESTAMPTZ DEFAULT NOW()
        )
        """,

        """
        CREATE TABLE IF NOT EXISTS memorias (
            id BIGSERIAL PRIMARY KEY,
            usuario_id BIGINT NOT NULL REFERENCES usuarios(id)
                ON DELETE CASCADE,
            conteudo TEXT NOT NULL,
            criada_em TIMESTAMPTZ DEFAULT NOW()
        )
        """,

        """
        CREATE INDEX IF NOT EXISTS conversas_usuario_idx
        ON conversas(usuario_id)
        """,

        """
        CREATE INDEX IF NOT EXISTS mensagens_conversa_idx
        ON mensagens(conversa_id)
        """,

        """
        CREATE INDEX IF NOT EXISTS memorias_usuario_idx
        ON memorias(usuario_id)
        """
    ]

    with conectar() as banco:
        with banco.cursor() as cursor:
            for comando in comandos:
                cursor.execute(comando)


# =========================================================
# SENHAS E SESSÕES
# =========================================================

def gerar_hash_senha(senha):
    salt = secrets.token_bytes(16)

    chave = hashlib.scrypt(
        senha.encode("utf-8"),
        salt=salt,
        n=16384,
        r=8,
        p=1
    )

    return salt.hex() + ":" + chave.hex()


def verificar_senha(senha, senha_hash):
    try:
        salt_hex, chave_hex = senha_hash.split(":")
        salt = bytes.fromhex(salt_hex)

        chave = hashlib.scrypt(
            senha.encode("utf-8"),
            salt=salt,
            n=16384,
            r=8,
            p=1
        )

        return hmac.compare_digest(
            chave.hex(),
            chave_hex
        )

    except Exception:
        return False


def criar_token():
    return secrets.token_urlsafe(48)


def hash_token(token):
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def definir_cookie(response, request, token):
    response.set_cookie(
        key="astra_session",
        value=token,
        httponly=True,
        secure=(
            request.headers.get("x-forwarded-proto") == "https"
            or request.url.scheme == "https"
        ),
        samesite="lax",
        max_age=60 * 60 * 24 * 30,
        path="/"
    )


# =========================================================
# INICIALIZAÇÃO
# =========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    inicializar_banco()
    print("PCNOT AI iniciada!")
    yield


app = FastAPI(
    title=NOME_APP,
    version=VERSAO,
    docs_url="/docs",
    lifespan=lifespan
)


# =========================================================
# MODELOS DE DADOS
# =========================================================

class Cadastro(BaseModel):
    username: str = Field(min_length=3, max_length=30)
    nome_exibicao: str = Field(min_length=2, max_length=50)
    finalidade: str = Field(default="", max_length=200)
    senha: str = Field(min_length=8, max_length=100)
    aceitou_termos: bool = False


class Login(BaseModel):
    username: str
    senha: str


class Mensagem(BaseModel):
    texto: str = Field(default="", max_length=10000)
    conversa_id: int | None = None
    image_data: str | None = Field(default=None, max_length=7000000)
    image_mime: str | None = None


class StatusUsuario(BaseModel):
    ativo: bool


# =========================================================
# AUTENTICAÇÃO
# =========================================================

def usuario_atual(request: Request):
    token = request.cookies.get("astra_session")

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Faça login para continuar."
        )

    token_criptografado = hash_token(token)

    with conectar() as banco:
        with banco.cursor() as cursor:
            cursor.execute(
                """
                SELECT u.*
                FROM sessoes s
                JOIN usuarios u ON u.id = s.usuario_id
                WHERE s.token_hash = %s
                  AND s.expira_em > NOW()
                """,
                (token_criptografado,)
            )

            usuario = cursor.fetchone()

    if not usuario:
        raise HTTPException(
            status_code=401,
            detail="Sessão inválida ou expirada."
        )

    if not usuario["ativo"]:
        raise HTTPException(
            status_code=403,
            detail="Esta conta está desativada."
        )

    return usuario


def exigir_admin(usuario=Depends(usuario_atual)):
    if not usuario["admin"]:
        raise HTTPException(
            status_code=403,
            detail="Acesso permitido somente ao administrador."
        )

    return usuario


# =========================================================
# VALIDAÇÃO DE ORIGEM
# =========================================================

def validar_origem(request: Request):
    origem = request.headers.get("origin")

    if not origem:
        return

    host_origem = origem.replace(
        "https://", ""
    ).replace("http://", "")

    host_requisicao = request.headers.get("host", "")

    if host_origem.split("/")[0].lower() != host_requisicao.lower():
        raise HTTPException(
            status_code=403,
            detail="Origem da requisição não permitida."
        )


# =========================================================
# ARQUIVOS ESTÁTICOS
# =========================================================

if not STATIC_DIR.exists():
    STATIC_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/")
def inicio():
    arquivo = STATIC_DIR / "index.html"

    if not arquivo.exists():
        raise HTTPException(
            404,
            "Página inicial não encontrada."
        )

    return FileResponse(arquivo)


@app.get("/termos")
def termos():
    arquivo = STATIC_DIR / "termos.html"

    if not arquivo.exists():
        raise HTTPException(
            404,
            "Página de termos não encontrada."
        )

    return FileResponse(arquivo)


app.mount(
    "/static",
    StaticFiles(directory=str(STATIC_DIR)),
    name="static"
)


# =========================================================
# STATUS
# =========================================================

@app.get("/status")
def status():
    return {
        "nome": NOME_APP,
        "status": "online",
        "modelo": MODELO,
        "modelo_visao": MODELO_VISAO,
        "provedor": "Groq"
    }


# =========================================================
# CADASTRO
# =========================================================

@app.post("/auth/register")
def registrar(
    dados: Cadastro,
    request: Request,
    response: Response
):
    validar_origem(request)

    if not dados.aceitou_termos:
        raise HTTPException(
            400,
            "Você precisa aceitar os termos para criar uma conta."
        )

    username = dados.username.strip().lower()
    nome = dados.nome_exibicao.strip()

    if not re.fullmatch(r"[a-zA-Z0-9_.-]+", username):
        raise HTTPException(
            400,
            "O usuário só pode ter letras, números, ponto, hífen e underline."
        )

    if len(nome) < 2:
        raise HTTPException(
            400,
            "Informe um nome de exibição válido."
        )

    senha_hash = gerar_hash_senha(dados.senha)

    try:
        with conectar() as banco:
            with banco.cursor() as cursor:
                cursor.execute(
                    "SELECT COUNT(*) AS total FROM usuarios"
                )

                total = cursor.fetchone()["total"]
                primeiro_usuario = total == 0

                cursor.execute(
                    """
                    INSERT INTO usuarios (
                        username,
                        nome_exibicao,
                        finalidade,
                        password_hash,
                        admin,
                        ativo,
                        termos_versao,
                        termos_aceitos_em
                    )
                    VALUES (%s, %s, %s, %s, %s, TRUE, %s, NOW())
                    RETURNING id
                    """,
                    (
                        username,
                        nome,
                        dados.finalidade.strip(),
                        senha_hash,
                        primeiro_usuario,
                        TERMOS_VERSAO
                    )
                )

                usuario_id = cursor.fetchone()["id"]

                token = criar_token()

                cursor.execute(
                    """
                    INSERT INTO sessoes (
                        usuario_id,
                        token_hash,
                        expira_em
                    )
                    VALUES (%s, %s, NOW() + INTERVAL '30 days')
                    """,
                    (usuario_id, hash_token(token))
                )

        definir_cookie(response, request, token)

        return {
            "sucesso": True,
            "mensagem": "Cadastro realizado com sucesso!",
            "usuario_id": usuario_id,
            "admin": primeiro_usuario
        }

    except psycopg.errors.UniqueViolation:
        raise HTTPException(
            409,
            "Esse nome de usuário já está em uso."
        )


# =========================================================
# LOGIN
# =========================================================

@app.post("/auth/login")
def login(
    dados: Login,
    request: Request,
    response: Response
):
    validar_origem(request)

    username = dados.username.strip().lower()

    with conectar() as banco:
        with banco.cursor() as cursor:
            cursor.execute(
                """
                SELECT *
                FROM usuarios
                WHERE LOWER(username) = %s
                """,
                (username,)
            )

            usuario = cursor.fetchone()

    if not usuario or not verificar_senha(
        dados.senha,
        usuario["password_hash"]
    ):
        raise HTTPException(
            401,
            "Usuário ou senha incorretos."
        )

    if not usuario["ativo"]:
        raise HTTPException(
            403,
            "Esta conta está desativada."
        )

    token = criar_token()

    with conectar() as banco:
        with banco.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO sessoes (
                    usuario_id,
                    token_hash,
                    expira_em
                )
                VALUES (%s, %s, NOW() + INTERVAL '30 days')
                """,
                (usuario["id"], hash_token(token))
            )

    definir_cookie(response, request, token)

    return {
        "sucesso": True,
        "mensagem": "Login realizado!",
        "usuario": {
            "id": usuario["id"],
            "username": usuario["username"],
            "nome_exibicao": usuario["nome_exibicao"],
            "finalidade": usuario["finalidade"],
            "admin": usuario["admin"]
        }
    }


# =========================================================
# USUÁRIO ATUAL
# =========================================================

@app.get("/auth/me")
def minha_conta(usuario=Depends(usuario_atual)):
    return {
        "usuario": {
            "id": usuario["id"],
            "username": usuario["username"],
            "nome_exibicao": usuario["nome_exibicao"],
            "finalidade": usuario["finalidade"],
            "admin": usuario["admin"]
        }
    }


# =========================================================
# LOGOUT
# =========================================================

@app.post("/auth/logout")
def logout(
    request: Request,
    response: Response,
    usuario=Depends(usuario_atual)
):
    token = request.cookies.get("astra_session")

    if token:
        with conectar() as banco:
            with banco.cursor() as cursor:
                cursor.execute(
                    """
                    DELETE FROM sessoes
                    WHERE token_hash = %s
                    """,
                    (hash_token(token),)
                )

    response.delete_cookie(
        "astra_session",
        path="/",
        httponly=True,
        samesite="lax"
    )

    return {
        "sucesso": True,
        "mensagem": "Você saiu da conta."
    }


# =========================================================
# CONVERSAS
# =========================================================

@app.get("/conversas")
def listar_conversas(usuario=Depends(usuario_atual)):
    with conectar() as banco:
        with banco.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    titulo,
                    criada_em AS data,
                    atualizada_em
                FROM conversas
                WHERE usuario_id = %s
                ORDER BY atualizada_em DESC
                """,
                (usuario["id"],)
            )

            conversas = cursor.fetchall()

    return {"conversas": conversas}


@app.post("/conversas")
def criar_conversa(usuario=Depends(usuario_atual)):
    with conectar() as banco:
        with banco.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO conversas (usuario_id, titulo)
                VALUES (%s, 'Nova conversa')
                RETURNING id
                """,
                (usuario["id"],)
            )

            conversa_id = cursor.fetchone()["id"]

    return {
        "sucesso": True,
        "conversa_id": conversa_id
    }


@app.get("/conversas/{conversa_id}")
def abrir_conversa(
    conversa_id: int,
    usuario=Depends(usuario_atual)
):
    with conectar() as banco:
        with banco.cursor() as cursor:
            cursor.execute(
                """
                SELECT *
                FROM conversas
                WHERE id = %s AND usuario_id = %s
                """,
                (conversa_id, usuario["id"])
            )

            conversa = cursor.fetchone()

            if not conversa:
                raise HTTPException(
                    404,
                    "Conversa não encontrada."
                )

            cursor.execute(
                """
                SELECT
                    id,
                    papel AS role,
                    conteudo AS content,
                    criada_em
                FROM mensagens
                WHERE conversa_id = %s AND usuario_id = %s
                ORDER BY criada_em ASC
                """,
                (conversa_id, usuario["id"])
            )

            mensagens = cursor.fetchall()

    return {
        "conversa": conversa,
        "mensagens": mensagens
    }


@app.delete("/conversas/{conversa_id}")
def excluir_conversa(
    conversa_id: int,
    usuario=Depends(usuario_atual)
):
    with conectar() as banco:
        with banco.cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM conversas
                WHERE id = %s AND usuario_id = %s
                RETURNING id
                """,
                (conversa_id, usuario["id"])
            )

            apagada = cursor.fetchone()

    if not apagada:
        raise HTTPException(
            404,
            "Conversa não encontrada."
        )

    return {"sucesso": True}


# =========================================================
# MEMÓRIAS
# =========================================================

@app.get("/memorias")
def listar_memorias(usuario=Depends(usuario_atual)):
    with conectar() as banco:
        with banco.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    conteudo,
                    criada_em AS data
                FROM memorias
                WHERE usuario_id = %s
                ORDER BY criada_em DESC
                """,
                (usuario["id"],)
            )

            memorias = cursor.fetchall()

    return {"memorias": memorias}


@app.delete("/memorias/{memoria_id}")
def excluir_memoria(
    memoria_id: int,
    usuario=Depends(usuario_atual)
):
    with conectar() as banco:
        with banco.cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM memorias
                WHERE id = %s AND usuario_id = %s
                RETURNING id
                """,
                (memoria_id, usuario["id"])
            )

            apagada = cursor.fetchone()

    if not apagada:
        raise HTTPException(
            404,
            "Memória não encontrada."
        )

    return {"sucesso": True}


# =========================================================
# PAINEL ADMINISTRATIVO
# =========================================================

@app.get("/admin/usuarios")
def admin_usuarios(usuario=Depends(exigir_admin)):
    with conectar() as banco:
        with banco.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    username,
                    nome_exibicao,
                    finalidade,
                    admin,
                    ativo,
                    criado_em AS data
                FROM usuarios
                ORDER BY criado_em DESC
                """
            )

            usuarios = cursor.fetchall()

    return {"usuarios": usuarios}


@app.patch("/admin/usuarios/{usuario_id}/status")
def admin_alterar_status(
    usuario_id: int,
    dados: StatusUsuario,
    usuario=Depends(exigir_admin)
):
    if usuario_id == usuario["id"] and not dados.ativo:
        raise HTTPException(
            400,
            "Você não pode desativar sua própria conta."
        )

    with conectar() as banco:
        with banco.cursor() as cursor:
            cursor.execute(
                """
                UPDATE usuarios
                SET ativo = %s
                WHERE id = %s
                RETURNING id
                """,
                (dados.ativo, usuario_id)
            )

            atualizado = cursor.fetchone()

    if not atualizado:
        raise HTTPException(
            404,
            "Usuário não encontrado."
        )

    return {"sucesso": True}


@app.get("/admin/conversas")
def admin_conversas(usuario=Depends(exigir_admin)):
    with conectar() as banco:
        with banco.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    c.id,
                    c.titulo,
                    c.usuario_id,
                    u.username,
                    u.nome_exibicao,
                    c.criada_em AS data,
                    c.atualizada_em
                FROM conversas c
                JOIN usuarios u ON u.id = c.usuario_id
                ORDER BY c.atualizada_em DESC
                """
            )

            conversas = cursor.fetchall()

    return {"conversas": conversas}


@app.get("/admin/conversas/{conversa_id}")
def admin_abrir_conversa(
    conversa_id: int,
    usuario=Depends(exigir_admin)
):
    with conectar() as banco:
        with banco.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    c.*,
                    u.username,
                    u.nome_exibicao
                FROM conversas c
                JOIN usuarios u ON u.id = c.usuario_id
                WHERE c.id = %s
                """,
                (conversa_id,)
            )

            conversa = cursor.fetchone()

            if not conversa:
                raise HTTPException(
                    404,
                    "Conversa não encontrada."
                )

            cursor.execute(
                """
                SELECT
                    id,
                    papel AS role,
                    conteudo AS content,
                    criada_em
                FROM mensagens
                WHERE conversa_id = %s
                ORDER BY criada_em ASC
                """,
                (conversa_id,)
            )

            mensagens = cursor.fetchall()

    return {
        "conversa": conversa,
        "mensagens": mensagens
    }


# =========================================================
# CLIMA
# =========================================================

CIDADES = {
    "belo horizonte": (-19.9167, -43.9345),
    "bh": (-19.9167, -43.9345),
    "são paulo": (-23.5505, -46.6333),
    "sao paulo": (-23.5505, -46.6333),
    "rio de janeiro": (-22.9068, -43.1729),
    "brasília": (-15.7939, -47.8828),
    "brasilia": (-15.7939, -47.8828),
    "curitiba": (-25.4284, -49.2733),
    "salvador": (-12.9777, -38.5016),
    "fortaleza": (-3.7319, -38.5267),
    "recife": (-8.0476, -34.8770)
}


def consultar_clima(cidade):
    chave = cidade.lower().strip()

    if chave not in CIDADES:
        return None

    latitude, longitude = CIDADES[chave]

    try:
        resposta = requests.get(
            TEMPO_URL,
            params={
                "latitude": latitude,
                "longitude": longitude,
                "current": (
                    "temperature_2m,"
                    "relative_humidity_2m,"
                    "apparent_temperature,"
                    "weather_code,"
                    "wind_speed_10m"
                ),
                "timezone": "America/Sao_Paulo"
            },
            timeout=15
        )

        resposta.raise_for_status()
        dados = resposta.json()["current"]

        return (
            f"Clima em {cidade.title()}:\n"
            f"Temperatura: {dados['temperature_2m']}°C\n"
            f"Sensação térmica: {dados['apparent_temperature']}°C\n"
            f"Umidade: {dados['relative_humidity_2m']}%\n"
            f"Vento: {dados['wind_speed_10m']} km/h"
        )

    except Exception as erro:
        print("Erro ao consultar clima:", erro)
        return "Não consegui consultar o clima agora."


def detectar_cidade(texto):
    texto = texto.lower()

    palavras_clima = [
        "clima",
        "tempo",
        "temperatura",
        "quente",
        "frio",
        "chuva"
    ]

    if not any(palavra in texto for palavra in palavras_clima):
        return None

    for cidade in CIDADES:
        if cidade in texto:
            return cidade

    return None


# =========================================================
# MEMÓRIAS DA IA
# =========================================================

def obter_memorias(usuario_id):
    with conectar() as banco:
        with banco.cursor() as cursor:
            cursor.execute(
                """
                SELECT conteudo
                FROM memorias
                WHERE usuario_id = %s
                ORDER BY criada_em DESC
                LIMIT 15
                """,
                (usuario_id,)
            )

            resultados = cursor.fetchall()

    return [
        item["conteudo"]
        for item in resultados
    ]


def salvar_memoria(usuario_id, conteudo):
    conteudo = conteudo.strip()

    if not conteudo or len(conteudo) > 500:
        return

    with conectar() as banco:
        with banco.cursor() as cursor:
            cursor.execute(
                """
                SELECT id
                FROM memorias
                WHERE usuario_id = %s
                  AND LOWER(conteudo) = LOWER(%s)
                LIMIT 1
                """,
                (usuario_id, conteudo)
            )

            if cursor.fetchone():
                return

            cursor.execute(
                """
                INSERT INTO memorias (usuario_id, conteudo)
                VALUES (%s, %s)
                """,
                (usuario_id, conteudo)
            )


# =========================================================
# PERSONALIDADE DA PCNOT AI
# =========================================================

def criar_sistema(usuario, memorias):
    sistema = f"""
Você é a PCNOT AI, uma inteligência artificial útil, clara e amigável.

Seu nome é PCNOT AI.
Responda sempre em português brasileiro, a menos que o usuário peça outro idioma.

Regras:
- Seja natural e direto.
- Explique assuntos difíceis de maneira simples.
- Ajude com estudos, programação, tecnologia e tarefas do dia a dia.
- Não invente informações.
- Se não souber algo, diga claramente.
- Use listas e exemplos quando ajudarem.
- Não diga que está usando Ollama.
- Você está sendo executada pela API Groq.
- Quando receber uma imagem, analise o que aparece nela.
- Se não conseguir identificar algo na imagem, seja sincera.

Nome de exibição do usuário: {usuario['nome_exibicao']}
Finalidade informada: {usuario['finalidade']}

Memórias do usuário:
"""

    if memorias:
        for memoria in memorias:
            sistema += f"\n- {memoria}"
    else:
        sistema += "\nNenhuma memória salva."

    return sistema


# =========================================================
# PREPARAÇÃO E VALIDAÇÃO DE IMAGENS
# =========================================================

def preparar_imagem(image_data, image_mime):
    if not image_data:
        if image_mime:
            raise HTTPException(
                400,
                "Foi informado um tipo de imagem sem enviar a imagem."
            )

        return None, None

    # Aceita tanto base64 puro quanto data URL.
    if image_data.startswith("data:"):
        cabecalho, separador, conteudo = image_data.partition(",")

        if not separador or ";base64" not in cabecalho:
            raise HTTPException(
                400,
                "Formato de imagem inválido."
            )

        mime_cabecalho = cabecalho[5:].split(";")[0].lower()

        if image_mime and image_mime.lower() != mime_cabecalho:
            raise HTTPException(
                400,
                "O tipo informado não corresponde à imagem."
            )

        image_mime = mime_cabecalho
        image_data = conteudo

    if not image_mime:
        raise HTTPException(
            400,
            "O tipo da imagem não foi informado."
        )

    image_mime = image_mime.lower().strip()

    if image_mime not in TIPOS_IMAGEM:
        raise HTTPException(
            400,
            "Formato não permitido. Envie JPG, PNG ou WEBP."
        )

    try:
        imagem_bytes = base64.b64decode(
            image_data,
            validate=True
        )

    except (binascii.Error, ValueError):
        raise HTTPException(
            400,
            "A imagem enviada está inválida."
        )

    if not imagem_bytes:
        raise HTTPException(
            400,
            "A imagem está vazia."
        )

    if len(imagem_bytes) > TAMANHO_MAXIMO_IMAGEM:
        raise HTTPException(
            413,
            "A imagem deve ter no máximo 5 MB."
        )

    # Confere a assinatura real do arquivo.
    assinatura_valida = False

    if image_mime == "image/jpeg":
        assinatura_valida = imagem_bytes.startswith(b"\xff\xd8\xff")

    elif image_mime == "image/png":
        assinatura_valida = imagem_bytes.startswith(
            b"\x89PNG\r\n\x1a\n"
        )

    elif image_mime == "image/webp":
        assinatura_valida = (
            len(imagem_bytes) >= 12
            and imagem_bytes[:4] == b"RIFF"
            and imagem_bytes[8:12] == b"WEBP"
        )

    if not assinatura_valida:
        raise HTTPException(
            400,
            "O arquivo não corresponde ao formato de imagem informado."
        )

    return image_data, image_mime


# =========================================================
# GROQ
# =========================================================

def gerar_resposta(historico, imagem_base64=None, imagem_mime=None):
    cabecalhos = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    modelo_escolhido = MODELO

    if imagem_base64:
        modelo_escolhido = MODELO_VISAO

        # A imagem é enviada somente nesta requisição.
        # Ela não é armazenada no banco de dados.
        mensagem_imagem = {
            "type": "image_url",
            "image_url": {
                "url": (
                    f"data:{imagem_mime};base64,{imagem_base64}"
                )
            }
        }

        # O conteúdo multimodal já é preparado no histórico.
        # Esta proteção evita enviar uma imagem sem conteúdo textual.
        for mensagem in reversed(historico):
            if mensagem["role"] == "user":
                if isinstance(mensagem["content"], str):
                    texto = mensagem["content"]

                    mensagem["content"] = [
                        {
                            "type": "text",
                            "text": texto
                        },
                        mensagem_imagem
                    ]

                break

    corpo = {
        "model": modelo_escolhido,
        "messages": historico,
        "temperature": 0.7,
        "max_completion_tokens": 2048
    }

    resposta = requests.post(
        GROQ_URL,
        headers=cabecalhos,
        json=corpo,
        timeout=120
    )

    if resposta.status_code != 200:
        print(
            "Erro Groq:",
            resposta.status_code,
            resposta.text[:2000]
        )

        raise RuntimeError(
            "A IA não conseguiu gerar uma resposta."
        )

    dados = resposta.json()

    conteudo = dados["choices"][0]["message"]["content"]

    if isinstance(conteudo, list):
        partes = []

        for parte in conteudo:
            if isinstance(parte, dict) and parte.get("type") == "text":
                partes.append(parte.get("text", ""))

        conteudo = "\n".join(partes)

    if not conteudo or not conteudo.strip():
        raise RuntimeError(
            "A IA retornou uma resposta vazia."
        )

    return conteudo.strip()


# =========================================================
# CONVERSAR
# =========================================================

@app.post("/conversar")
def conversar(
    dados: Mensagem,
    request: Request,
    usuario=Depends(usuario_atual)
):
    limitar_requisicoes(str(usuario["id"]))

    mensagem_usuario = dados.texto.strip()

    imagem_base64, imagem_mime = preparar_imagem(
        dados.image_data,
        dados.image_mime
    )

    if not mensagem_usuario and not imagem_base64:
        raise HTTPException(
            400,
            "Digite uma mensagem ou envie uma imagem."
        )

    if not mensagem_usuario and imagem_base64:
        mensagem_usuario = "Analise esta imagem e me explique o que aparece nela."

    conteudo_salvo = mensagem_usuario

    if imagem_base64:
        conteudo_salvo += "\n[Imagem anexada]"

    conversa_id = dados.conversa_id

    # -----------------------------------------------------
    # Verifica ou cria conversa e salva mensagem do usuário.
    # -----------------------------------------------------

    with conectar() as banco:
        with banco.cursor() as cursor:

            if conversa_id:
                cursor.execute(
                    """
                    SELECT id
                    FROM conversas
                    WHERE id = %s AND usuario_id = %s
                    """,
                    (conversa_id, usuario["id"])
                )

                conversa = cursor.fetchone()

                if not conversa:
                    raise HTTPException(
                        404,
                        "Conversa não encontrada."
                    )

            else:
                titulo = mensagem_usuario[:45] or "Imagem enviada"

                cursor.execute(
                    """
                    INSERT INTO conversas (usuario_id, titulo)
                    VALUES (%s, %s)
                    RETURNING id
                    """,
                    (usuario["id"], titulo)
                )

                conversa_id = cursor.fetchone()["id"]

            cursor.execute(
                """
                INSERT INTO mensagens (
                    conversa_id,
                    usuario_id,
                    papel,
                    conteudo
                )
                VALUES (%s, %s, 'user', %s)
                """,
                (
                    conversa_id,
                    usuario["id"],
                    conteudo_salvo
                )
            )

            cursor.execute(
                """
                SELECT papel, conteudo
                FROM mensagens
                WHERE conversa_id = %s
                ORDER BY criada_em DESC
                LIMIT 20
                """,
                (conversa_id,)
            )

            mensagens = list(reversed(cursor.fetchall()))

            cursor.execute(
                """
                UPDATE conversas
                SET atualizada_em = NOW()
                WHERE id = %s
                """,
                (conversa_id,)
            )

    # -----------------------------------------------------
    # Consulta de clima.
    # Se houver imagem, a IA analisa a imagem normalmente.
    # -----------------------------------------------------

    cidade = None

    if not imagem_base64:
        cidade = detectar_cidade(mensagem_usuario)

    if cidade:
        resposta_ia = consultar_clima(cidade)

        if not resposta_ia:
            resposta_ia = (
                "Não encontrei essa cidade na minha lista de consulta."
            )

    else:
        memorias = obter_memorias(usuario["id"])

        historico = [
            {
                "role": "system",
                "content": criar_sistema(usuario, memorias)
            }
        ]

        for item in mensagens:
            historico.append({
                "role": item["papel"],
                "content": item["conteudo"]
            })

        try:
            resposta_ia = gerar_resposta(
                historico,
                imagem_base64=imagem_base64,
                imagem_mime=imagem_mime
            )

        except requests.Timeout:
            raise HTTPException(
                504,
                "A PCNOT AI demorou para responder. Tente novamente."
            )

        except requests.RequestException as erro:
            print("Erro de conexão com Groq:", erro)

            raise HTTPException(
                502,
                "Não consegui conectar à inteligência artificial."
            )

        except Exception as erro:
            print("Erro ao conversar:", erro)

            raise HTTPException(
                502,
                "Não consegui gerar uma resposta agora. Tente novamente."
            )

    # -----------------------------------------------------
    # Salva resposta da IA.
    # -----------------------------------------------------

    with conectar() as banco:
        with banco.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO mensagens (
                    conversa_id,
                    usuario_id,
                    papel,
                    conteudo
                )
                VALUES (%s, %s, 'assistant', %s)
                """,
                (
                    conversa_id,
                    usuario["id"],
                    resposta_ia
                )
            )

            cursor.execute(
                """
                UPDATE conversas
                SET atualizada_em = NOW()
                WHERE id = %s
                """,
                (conversa_id,)
            )

    return {
        "resposta": resposta_ia,
        "conversa_id": conversa_id
    }
