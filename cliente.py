# cliente.py (FINAL)

import socket
import os
import requests # Importa a biblioteca para requisições HTTP
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.padding import PKCS7

# --- Configurações Iniciais ---
HOST = '127.0.0.1'
PORT = 65432
USERNAME_CLIENTE = 'cliente'

# Configuração do Servidor de Chaves Públicas ---
USAR_GIST = True
URL_BASE_GIST = "https://gist.github.com/Soeleve/a424bc66836f71b88327cc7958ea138c/raw" # Ex: Use a sua URL base do Gist aqui
URL_BASE_LOCAL = "http://127.0.0.1:8000"

# Parâmetros Diffie-Hellman (DH) ---
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
g = 2
numeros_parametros_dh = dh.DHParameterNumbers(p, g)
parametros_dh = numeros_parametros_dh.parameters()

# Caminhos para as chaves ---
CAMINHO_CHAVE_PRIVADA_CLIENTE = os.path.join('chaves', 'ecdsa_priv_cliente.pem')

# Constantes para Derivação de Chave ---
SALT = b'trabalho_pratico_salt'
ITERACOES_PBKDF2 = 100000
TAMANHO_CHAVE_AES = 32
TAMANHO_CHAVE_HMAC = 32

# --- Funções Auxiliares ---

def carregar_chave_privada_ecdsa(caminho):
    with open(caminho, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

# Função para baixar a chave pública de uma URL
def baixar_chave_publica_ecdsa(username):
    """Baixa e carrega a chave pública ECDSA de um usuário a partir de uma URL."""
    base_url = URL_BASE_GIST if USAR_GIST else URL_BASE_LOCAL
    url = f"{base_url}/{username}.keys"
    print(f"[Cliente] Baixando a chave pública do servidor de: {url}")
    
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        chave_publica = serialization.load_pem_public_key(response.content)
        return chave_publica
    except requests.exceptions.RequestException as e:
        print(f"[Cliente] ERRO: Falha ao baixar a chave pública: {e}")
        return None
    except Exception as e:
        print(f"[Cliente] ERRO: O conteúdo baixado não é uma chave pública válida. {e}")
        return None

def derivar_chaves(chave_mestra_dh):
    
    print("[Cliente] Derivando chaves AES e HMAC a partir do segredo DH...")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=TAMANHO_CHAVE_AES + TAMANHO_CHAVE_HMAC, salt=SALT, iterations=ITERACOES_PBKDF2)
    chaves_derivadas = kdf.derive(chave_mestra_dh)
    key_aes = chaves_derivadas[:TAMANHO_CHAVE_AES]
    key_hmac = chaves_derivadas[TAMANHO_CHAVE_AES:]
    print("[Cliente] Chaves derivadas com sucesso.")
    return key_aes, key_hmac

def enviar_dados(sock, dados):
    
    sock.sendall(len(dados).to_bytes(4, 'big') + dados)

def receber_dados(sock):
    
    tamanho_bytes = sock.recv(4)
    if not tamanho_bytes: return None
    tamanho = int.from_bytes(tamanho_bytes, 'big')
    return sock.recv(tamanho)

# --- Lógica Principal do Cliente ---
def main():
    chave_privada_cliente = carregar_chave_privada_ecdsa(CAMINHO_CHAVE_PRIVADA_CLIENTE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[Cliente] Conectado ao servidor em {HOST}:{PORT}")

        # --- Início do Handshake ---
        print("[Cliente] Gerando par de chaves DH do cliente...")
        chave_privada_dh_cliente = parametros_dh.generate_private_key()
        chave_publica_dh_cliente = chave_privada_dh_cliente.public_key()
        chave_publica_dh_cliente_bytes = chave_publica_dh_cliente.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        
        print("[Cliente] Assinando a própria chave pública DH...")
        dados_para_assinar_cliente = chave_publica_dh_cliente_bytes + USERNAME_CLIENTE.encode('utf-8')
        assinatura_cliente = chave_privada_cliente.sign(dados_para_assinar_cliente, ec.ECDSA(hashes.SHA256()))

        print("[Cliente] Enviando chave pública DH, assinatura e username para o servidor...")
        enviar_dados(s, chave_publica_dh_cliente_bytes)
        enviar_dados(s, assinatura_cliente)
        enviar_dados(s, USERNAME_CLIENTE.encode('utf-8'))

        print("[Cliente] Aguardando chave pública DH e assinatura do servidor...")
        chave_publica_dh_servidor_bytes = receber_dados(s)
        assinatura_servidor = receber_dados(s)
        username_servidor = receber_dados(s).decode('utf-8')
        
        # Usa a nova função para baixar a chave
        chave_publica_ecdsa_servidor = baixar_chave_publica_ecdsa(username_servidor)
        if not chave_publica_ecdsa_servidor:
            print("[Cliente] Abortando handshake.")
            return

        print(f"[Cliente] Chave pública de '{username_servidor}' baixada. Verificando assinatura...")
        dados_para_verificar = chave_publica_dh_servidor_bytes + username_servidor.encode('utf-8')
        
        try:
            chave_publica_ecdsa_servidor.verify(assinatura_servidor, dados_para_verificar, ec.ECDSA(hashes.SHA256()))
            print("[Cliente] Assinatura do servidor é VÁLIDA.")
        except Exception as e:
            print(f"[Cliente] ERRO: Assinatura do servidor INVÁLIDA! {e}")
            return
            
        
        print("[Cliente] Calculando o segredo compartilhado (DH)...")
        chave_publica_dh_servidor = serialization.load_pem_public_key(chave_publica_dh_servidor_bytes)
        segredo_compartilhado = chave_privada_dh_cliente.exchange(chave_publica_dh_servidor)
        
        key_aes, key_hmac = derivar_chaves(segredo_compartilhado)
        
        print("\n[Cliente] Handshake completo. Preparando para enviar mensagem segura.")
        
        mensagem_original = input("Digite a mensagem a ser enviada: ").encode('utf-8')
        
        iv_aes = os.urandom(16)
        
        padder = PKCS7(algorithms.AES.block_size).padder()
        mensagem_padded = padder.update(mensagem_original) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(key_aes), modes.CBC(iv_aes))
        encryptor = cipher.encryptor()
        mensagem_criptografada = encryptor.update(mensagem_padded) + encryptor.finalize()
        
        h = HMAC(key_hmac, hashes.SHA256())
        h.update(iv_aes + mensagem_criptografada)
        hmac_tag = h.finalize()
        
        pacote_final = hmac_tag + iv_aes + mensagem_criptografada
        s.sendall(pacote_final)
        
        print("\n[Cliente] Mensagem segura enviada para o servidor.")

if __name__ == "__main__":
    main()