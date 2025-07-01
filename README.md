# Trabalho-Seguran-a_informacao
# Trabalho Prático 1 — Sistema de Mensagens Seguras

Este projeto implementa um canal de comunicação segura entre um cliente e um servidor em Python, utilizando criptografia moderna e verificação de autenticidade digital.

## Requisitos de Segurança Atendidos

- **Confidencialidade:** AES (CBC) para proteger o conteúdo das mensagens.
- **Integridade:** HMAC (SHA-256) para detectar qualquer modificação.
- **Autenticidade:** ECDSA para autenticar as chaves DH trocadas e garantir a origem legítima.

## Estrutura do Projeto

```
.
├── cliente.py                  # Código do cliente (envia mensagens seguras)
├── servidor.py                 # Código do servidor (valida e decifra)
├── gerador_chaves_ecdsa.py     # Gera as chaves ECDSA
├── chaves/
│   ├── ecdsa_priv_cliente.pem
│   ├── ecdsa_pub_cliente.pem
│   ├── ecdsa_priv_servidor.pem
│   ├── ecdsa_pub_servidor.pem
│   └── github_mock/
│       ├── cliente.keys
│       └── servidor.keys
```

## Como Executar

1. **Gere as chaves ECDSA:**
```bash
python gerador_chaves_ecdsa.py
```

2. **Inicie um servidor HTTP local para simular o GitHub:**
```bash
python -m http.server --directory chaves/github_mock 8000
```

3. **Em outro terminal, execute o servidor seguro:**
```bash
python servidor.py
```

4. **Em outro terminal, execute o cliente:**
```bash
python cliente.py
```

5. Digite uma mensagem no cliente e veja a mágica acontecer!

## Tecnologias Usadas

- `cryptography` — Biblioteca de criptografia moderna
- `requests` — Requisições HTTP para baixar chaves públicas ECDSA
- `socket` — Comunicação de rede cliente-servidor

## Segurança Detalhada

- **Handshake autenticado:** Assinatura ECDSA + validação com chaves públicas baixadas via HTTP.
- **Troca segura de chaves:** Diffie-Hellman com parâmetros fixos (RFC 3526 - Grupo 14).
- **Derivação de chaves:** PBKDF2 com 100.000 iterações e salt fixo.
- **Encrypt-then-MAC:** A forma correta de proteger e autenticar mensagens.

## Formato da Mensagem

```
[HMAC_TAG (32B)] + [IV_AES (16B)] + [MENSAGEM_CRIPTOGRAFADA]
```

## Testes de Segurança Sugeridos

- Modifique manualmente o HMAC_TAG ou IV antes do envio → mensagem será rejeitada.
- Remova a assinatura → handshake será abortado.
- Use uma chave pública falsa → handshake será abortado.

---

Este projeto é uma simulação acadêmica de como funciona a segurança de canais criptografados modernos.

