# gerador_chaves_ecdsa.py

import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

def gerar_e_salvar_chaves_ecdsa(nome_base):
    """
    Gera um par de chaves ECDSA (privada e pública) e as salva em arquivos .pem.
    """
    # Cria o diretório 'chaves' se ele não existir
    if not os.path.exists('chaves'):
        os.makedirs('chaves')

    # Gera a chave privada ECDSA usando a curva SECP256R1
    # Esta é uma curva padrão e amplamente utilizada para ECDSA.
    chave_privada = ec.generate_private_key(ec.SECP256R1())

    # Gera a chave pública correspondente
    chave_publica = chave_privada.public_key()

    # Serializa a chave privada para o formato PEM.
    # PEM é um formato de texto padrão para armazenar chaves criptográficas.
    # Usamos um formato específico (PKCS8) e sem criptografia para o arquivo (a proteção
    # do arquivo em si fica a cargo do sistema operacional).
    pem_privada = chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serializa a chave pública para o formato PEM.
    # O formato SubjectPublicKeyInfo é um padrão para chaves públicas.
    pem_publica = chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Salva as chaves em arquivos
    caminho_privado = os.path.join('chaves', f'ecdsa_priv_{nome_base}.pem')
    caminho_publico = os.path.join('chaves', f'ecdsa_pub_{nome_base}.pem')

    with open(caminho_privado, 'wb') as f:
        f.write(pem_privada)
    print(f"Chave privada salva em: {caminho_privado}")

    with open(caminho_publico, 'wb') as f:
        f.write(pem_publica)
    print(f"Chave pública salva em: {caminho_publico}")


if __name__ == "__main__":
    print("Gerando chaves para o CLIENTE...")
    gerar_e_salvar_chaves_ecdsa("cliente")
    print("\nGerando chaves para o SERVIDOR...")
    gerar_e_salvar_chaves_ecdsa("servidor")