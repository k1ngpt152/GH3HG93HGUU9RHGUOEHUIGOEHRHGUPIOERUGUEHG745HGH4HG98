from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
import json
import os # Será usado apenas para variáveis de ambiente, se necessário
import uuid
from urllib.parse import unquote_plus
import base64
import zlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from typing import Dict, Any, Optional, List # Para type hints

# --- Configuração da API ---
app = FastAPI(
    title="Mock PrivateBin API",
    description="Simulação de um servidor PrivateBin para receber e visualizar pastes (não persistente).",
    version="1.0.0"
)

# --- Armazenamento em Memória (Não Persistente) ---
# Estes dicionários manterão os dados enquanto o servidor estiver rodando.
# Serão resetados a cada reinicialização do servidor no Render.
PASTES: Dict[str, Dict[str, Any]] = {} # paste_id -> payload_data (adata, ct, meta)
DELETE_TOKENS: Dict[str, str] = {}    # paste_id -> delete_token

MALWARE_FIXED_PASSWORD = "7IvaKi$yAVb0" # A senha que o malware usa com a passphrase

# --- Funções de Criptografia (mesmas do servidor mock anterior) ---
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

# --- Modelos Pydantic (para validação do corpo da requisição POST) ---
from pydantic import BaseModel, Field

class PasteMeta(BaseModel):
    expire: str

class PastePayload(BaseModel):
    v: int
    adata: List[Any] # 'adata' é uma lista complexa
    ct: str # Ciphertext em Base64
    meta: PasteMeta
    # Se você modificou o malware para enviar a chave, adicione aqui:
    # mock_key_b58: Optional[str] = None 

# --- Endpoints da API ---

@app.post("/", response_model=Dict[str, Any])
async def create_paste(payload: PastePayload):
    """
    Recebe um novo paste criptografado.
    O corpo da requisição deve ser um JSON مطابق com o formato do PrivateBin.
    """
    # Payload original do PrivateBin (sem mock_key_b58)
    # Se você quer que o servidor descriptografe automaticamente (requer mock_key_b58 no payload)
    # você precisaria adicionar a lógica aqui. Por agora, apenas salva criptografado.

    paste_id = str(uuid.uuid4())
    delete_token = str(uuid.uuid4().hex)

    # Armazena o payload em memória (sem o mock_key_b58, se presente)
    # A validação Pydantic já garantiu que temos adata, ct, meta
    PASTES[paste_id] = {
        "adata": payload.adata,
        "ct": payload.ct,
        "meta": payload.meta.dict() # Converte Pydantic model para dict
    }
    DELETE_TOKENS[paste_id] = delete_token

    print(f"\n--- Novo Paste Criptografado Recebido (API) ---")
    print(f"  ID do Paste: {paste_id}")
    # Não vamos salvar em arquivo aqui, está em memória

    return {
        "status": 0,
        "id": paste_id,
        "url": f"/?pasteid={paste_id}", # URL relativa para visualização
        "deletetoken": delete_token
    }

@app.get("/", response_class=HTMLResponse)
async def view_paste_or_list(
    pasteid: Optional[str] = Query(None, alias="pasteid"), # Se a URL for /?pasteid=ID
    b58key: Optional[str] = Query(None, alias="b58key")   # Se a URL for /?pasteid=ID&b58key=CHAVE
):
    """
    Serve a página principal para listar pastes ou a página de um paste específico
    com a opção de descriptografia interativa.
    """
    if b58key: # Decodifica a chave se veio de um formulário GET
        b58key_unquoted = unquote_plus(b58key)
    else:
        b58key_unquoted = None

    if pasteid: # Mostrar página de um paste específico
        paste_data_saved = PASTES.get(pasteid)
        if not paste_data_saved:
            return HTMLResponse(content=f"<html><body><h1>404 - Paste Não Encontrado</h1><p>ID: '{pasteid}'</p></body></html>", status_code=404)

        adata_obj = paste_data_saved.get('adata')
        ct_b64_str = paste_data_saved.get('ct')
        decrypted_output_html = "<p><em>Insira a chave Base58 para tentar a descriptografia.</em></p>"

        if b58key_unquoted and adata_obj and ct_b64_str:
            print(f"Tentando descriptografar (API) paste {pasteid} com chave: {b58key_unquoted[:10]}...")
            decrypted_content_bytes = server_side_decrypt(
                b58key_unquoted,
                MALWARE_FIXED_PASSWORD,
                adata_obj,
                ct_b64_str
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
        
        html_content = f"""
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
        </body></html>
        """
        return HTMLResponse(content=html_content)
    
    else: # Mostrar página principal com lista de pastes
        body = "<html><head><title>Mock PrivateBin API (FastAPI)</title>"
        body += "<style>body {font-family: sans-serif;} li a {text-decoration: none;} li a:hover {text-decoration: underline;}</style></head>"
        body += "<body><h1>Mock PrivateBin API (FastAPI)</h1><h3>Pastes Recebidos (em memória):</h3><ul>"
        if PASTES:
            for pid in sorted(PASTES.keys(), reverse=True):
                body += f"<li><a href='/?pasteid={pid}'>{pid}</a></li>"
        else:
            body += "<li>Nenhum paste recebido ainda.</li>"
        body += "</ul></body></html>"
        return HTMLResponse(content=body)

@app.delete("/", response_model=Dict[str, Any])
async def delete_paste_api(pasteid: str = Query(...), deletetoken: str = Query(...)):
    """
    Deleta um paste usando o pasteid e o deletetoken.
    """
    print(f"\n--- Tentativa de DELETE (API) ---")
    print(f"  Paste ID para deletar: {pasteid}")
    print(f"  Token fornecido: {deletetoken}")

    correct_token = DELETE_TOKENS.get(pasteid)
    if correct_token and correct_token == deletetoken:
        if pasteid in PASTES:
            del PASTES[pasteid]
            del DELETE_TOKENS[pasteid]
            message = f"Paste {pasteid} deletado da memória."
            status_code = 200
            print(f"  {message}")
        else: # Token existe mas paste já sumiu? Improvável se sincronizado.
            del DELETE_TOKENS[pasteid] # Remove o token órfão
            message = f"Token para paste {pasteid} removido, mas o paste não estava na memória."
            status_code = 404 
            print(f"  {message}")
    else:
        message = "Erro: Token de exclusão inválido ou paste ID não encontrado."
        status_code = 401 # Unauthorized ou Not Found
        print(f"  Falha no DELETE (API): {message}")
    
    if status_code != 200:
        raise HTTPException(status_code=status_code, detail=message)
    
    return {"status": 0, "message": message}


@app.get("/ping", response_model=Dict[str, str])
async def ping():
    """
    Endpoint simples para verificar se a API está rodando.
    """
    return {"message": "pong"}

# Para rodar localmente com uvicorn:
# uvicorn main:app --reload
