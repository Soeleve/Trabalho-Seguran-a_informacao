# servidor.py

import socket
import os
import requests # NOVO: Importa a biblioteca para requisições HTTP
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.padding import PKCS7
import hmac as hmac_compare

# --- Configurações Iniciais ---
HOST = '127.0.0.1'
PORT = 65432
USERNAME_SERVIDOR = 'servidor'

# Configuração do Servidor de Chaves Públicas ---
URL_BASE_GIST = "https://gist.github.com/Soeleve/a424bc66836f71b88327cc7958ea138c/raw" # Ex: Use a sua URL base do Gist aqui


# --- Parâmetros Diffie-Hellman (DH) ---
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
g = 2
numeros_parametros_dh = dh.DHParameterNumbers(p, g)
parametros_dh = numeros_parametros_dh.parameters()

# --- Caminhos para as chaves ---
CAMINHO_CHAVE_PRIVADA_SERVIDOR = os.path.join('chaves', 'ecdsa_priv_servidor.pem')

# --- Constantes para Derivação de Chave ---
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
    base_url = URL_BASE_GIST
    url = f"{base_url}/{username}.keys"
    print(f"[Servidor] Baixando a chave pública do cliente de: {url}")
    
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status() # Lança um erro para respostas 4xx/5xx
        
        # Carrega a chave diretamente do conteúdo baixado
        chave_publica = serialization.load_pem_public_key(response.content)
        return chave_publica
    except requests.exceptions.RequestException as e:
        print(f"[Servidor] ERRO: Falha ao baixar a chave pública: {e}")
        return None
    except Exception as e:
        print(f"[Servidor] ERRO: O conteúdo baixado não é uma chave pública válida. {e}")
        return None

def derivar_chaves(chave_mestra_dh):
    
    print("[Servidor] Derivando chaves AES e HMAC a partir do segredo DH...")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=TAMANHO_CHAVE_AES + TAMANHO_CHAVE_HMAC, salt=SALT, iterations=ITERACOES_PBKDF2)
    chaves_derivadas = kdf.derive(chave_mestra_dh)
    key_aes = chaves_derivadas[:TAMANHO_CHAVE_AES]
    key_hmac = chaves_derivadas[TAMANHO_CHAVE_AES:]
    print("[Servidor] Chaves derivadas com sucesso.")
    return key_aes, key_hmac

def enviar_dados(sock, dados):
    
    sock.sendall(len(dados).to_bytes(4, 'big') + dados)

def receber_dados(sock):
    
    tamanho_bytes = sock.recv(4)
    if not tamanho_bytes: return None
    tamanho = int.from_bytes(tamanho_bytes, 'big')
    return sock.recv(tamanho)

# --- Lógica Principal do Servidor ---

def main():
    chave_privada_servidor = carregar_chave_privada_ecdsa(CAMINHO_CHAVE_PRIVADA_SERVIDOR)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[Servidor] Ouvindo em {HOST}:{PORT}")
        
        conn, addr = s.accept()
        with conn:
            print(f"[Servidor] Conectado por {addr}")

            # --- Início do Handshake ---
            
            print("[Servidor] Aguardando chave pública DH e assinatura do cliente...")
            chave_publica_dh_cliente_bytes = receber_dados(conn)
            assinatura_cliente = receber_dados(conn)
            username_cliente = receber_dados(conn).decode('utf-8')

            # Usa a função para baixar a chave
            chave_publica_ecdsa_cliente = baixar_chave_publica_ecdsa(username_cliente)
            if not chave_publica_ecdsa_cliente:
                print("[Servidor] Abortando handshake.")
                return

            print(f"[Servidor] Chave pública de '{username_cliente}' baixada. Verificando assinatura...")
            
            dados_para_verificar = chave_publica_dh_cliente_bytes + username_cliente.encode('utf-8')
            
            try:
                chave_publica_ecdsa_cliente.verify(assinatura_cliente, dados_para_verificar, ec.ECDSA(hashes.SHA256()))
                print("[Servidor] Assinatura do cliente é VÁLIDA.")
            except Exception as e:
                print(f"[Servidor] ERRO: Assinatura do cliente INVÁLIDA! {e}")
                return

            
            print("[Servidor] Gerando par de chaves DH do servidor...")
            chave_privada_dh_servidor = parametros_dh.generate_private_key()
            chave_publica_dh_servidor = chave_privada_dh_servidor.public_key()
            
            chave_publica_dh_servidor_bytes = chave_publica_dh_servidor.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

            print("[Servidor] Assinando a própria chave pública DH...")
            dados_para_assinar_servidor = chave_publica_dh_servidor_bytes + USERNAME_SERVIDOR.encode('utf-8')
            assinatura_servidor = chave_privada_servidor.sign(dados_para_assinar_servidor, ec.ECDSA(hashes.SHA256()))
            
            print("[Servidor] Enviando chave pública DH e assinatura para o cliente...")
            enviar_dados(conn, chave_publica_dh_servidor_bytes)
            enviar_dados(conn, assinatura_servidor)
            enviar_dados(conn, USERNAME_SERVIDOR.encode('utf-8'))
            
            print("[Servidor] Calculando o segredo compartilhado (DH)...")
            chave_publica_dh_cliente = serialization.load_pem_public_key(chave_publica_dh_cliente_bytes)
            segredo_compartilhado = chave_privada_dh_servidor.exchange(chave_publica_dh_cliente)
            
            key_aes, key_hmac = derivar_chaves(segredo_compartilhado)
            
            print("\n[Servidor] Handshake completo. Aguardando mensagem segura...")
            
            pacote_recebido = conn.recv(4096)
            if not pacote_recebido:
                print("[Servidor] Cliente desconectou antes de enviar a mensagem.")
                return

            hmac_recebido = pacote_recebido[:32]
            iv_aes = pacote_recebido[32:48]
            mensagem_criptografada = pacote_recebido[48:]

            print("[Servidor] Verificando HMAC da mensagem...")
            h = HMAC(key_hmac, hashes.SHA256())
            h.update(iv_aes + mensagem_criptografada)
            hmac_calculado = h.finalize()
            
            if not hmac_compare.compare_digest(hmac_recebido, hmac_calculado):
                print("[Servidor] ERRO: HMAC da mensagem é INVÁLIDO! Mensagem descartada.")
                return
            
            print("[Servidor] HMAC válido. A mensagem é íntegra e autêntica.")

            print("[Servidor] Descriptografando a mensagem...")
            cipher = Cipher(algorithms.AES(key_aes), modes.CBC(iv_aes))
            decryptor = cipher.decryptor()
            
            mensagem_padded = decryptor.update(mensagem_criptografada) + decryptor.finalize()
            unpadder = PKCS7(algorithms.AES.block_size).unpadder()
            mensagem_original = unpadder.update(mensagem_padded) + unpadder.finalize()
            
            print("\n" + "="*50)
            print("  MENSAGEM RECEBIDA COM SUCESSO")
            print("="*50)
            print(f"  Mensagem: {mensagem_original.decode('utf-8')}")
            print("="*50 + "\n")

if __name__ == "__main__":
    main()