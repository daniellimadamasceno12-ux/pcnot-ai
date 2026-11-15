from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import requests

app = FastAPI(title="ASTRA", docs_url="/docs")

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)


class Mensagem(BaseModel):
    texto: str
    historico: list[dict] = Field(default_factory=list)


@app.get("/")
def inicio():
    return FileResponse("static/index.html")


@app.post("/conversar")
def conversar(mensagem: Mensagem):
    try:
        contexto = ""

        for item in mensagem.historico[-20:]:
            papel = (
                "Usuário"
                if item.get("role") == "user"
                else "ASTRA"
            )
            conteudo = item.get("content", "")

            if isinstance(conteudo, str) and conteudo.strip():
                contexto += f"{papel}: {conteudo}\n"

        prompt = contexto + f"Usuário: {mensagem.texto}\nASTRA:"

        resposta = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "qwen3:4b",
                "system": """
Você é ASTRA, uma assistente pessoal de inteligência artificial.

REGRAS:
- Responda em português brasileiro correto.
- Seja natural, clara e objetiva.
- Evite repetições e apresentações desnecessárias.
- Ajude com estudos, programação, tecnologia e organização.
- Seja honesta sobre suas capacidades e limitações.

IDENTIDADE:
- Seu nome é ASTRA.
- Você é uma assistente inteligente e personalizável.
- Não se apresente como Qwen ou Alibaba Cloud.
""",
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.3
                }
            },
            timeout=120
        )

        resposta.raise_for_status()
        dados = resposta.json()

        return {"resposta": dados["response"]}

    except requests.RequestException as erro:
        return {
            "resposta": f"Erro ao acessar a IA: {erro}"
        }
