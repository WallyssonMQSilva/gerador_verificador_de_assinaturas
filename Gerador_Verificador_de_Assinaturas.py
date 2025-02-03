import random
import hashlib
import base64
from math import gcd
from sympy import nextprime
import os

def PseudoPrimoForte(n, b):
    q = n - 1
    k = 0
    while q % 2 == 0:
        q //= 2
        k += 1
    r = pow(b, q, n)
    if r == 1:
        return True
    for _ in range(k):
        if r == n - 1:
            return True
        r = r * r % n
    return False

def TesteMillerRabin(n, k):
    for _ in range(k):
        b = random.randint(2, n - 1)
        if not PseudoPrimoForte(n, b):
            return False
    return True

def Geracao_de_Chave(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    verificador = True
    while verificador:
        e = int(input('Escolha o "e" tal que o mdc entre "e" e "phi" seja = 1 e "e" seja menor que "phi": '))
        if gcd((e,phi) == 1):
            verificador = False
        else:
            print(' A chave pública "e" escolhida tem o mdc(e, φ(n)), difente de 1, logo é uma chave inválida.')
    d = pow(e, -1, phi)
    # e = 65537
    return [e, n], [d, n]

def Hash(mensagem):
    return hashlib.sha256(mensagem.encode()).hexdigest()

def mgf1(seed, length, hash_func=hashlib.sha256):
    counter = 0
    output = b''
    while len(output) < length:
        counter_bytes = counter.to_bytes(4, byteorder='big')
        output += hash_func(seed + counter_bytes).digest()
        counter += 1
    return output[:length]

def oaep_encode(message, n_length, label=b"", hash_func=hashlib.sha256):
    hash_len = hash_func().digest_size
    max_msg_len = n_length - 2 * hash_len - 2
    if max_msg_len <= 0:
        raise ValueError("Tamanho da chave n_length muito pequeno para a função de hash escolhida")
    if len(message) > max_msg_len:
        raise ValueError("Mensagem muito longa para OAEP")

    # Passo 1: Hash do rótulo
    label_hash = hash_func(label).digest()

    # Passo 2: Criar string de preenchimento PS
    ps = b'\x00' * (max_msg_len - len(message))

    # Passo 3: Construir DB = lHash || PS || 0x01 || M
    db = label_hash + ps + b'\x01' + message

    # Passo 4: Gerar semente aleatória
    seed = random.getrandbits(hash_len * 8).to_bytes(hash_len, byteorder='big')

    # Passo 5: Gerar máscara para DB
    db_mask = mgf1(seed, len(db), hash_func)

    # Passo 6: Aplicar máscara no DB
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))

    # Passo 7: Gerar máscara para a semente
    seed_mask = mgf1(masked_db, hash_len, hash_func)

    # Passo 8: Aplicar máscara na semente
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))

    EM = b'\x00' + masked_seed + masked_db

    # Passo 9: Construir EM = 0x00 || maskedSeed || maskedDB
    return EM


def oaep_decode(encoded, n_length, label=b"", hash_func=hashlib.sha256):
    hash_len = hash_func().digest_size
    # Passo 1: Verificar se o primeiro byte é 0x00
    if encoded[0] != 0x00:
        raise ValueError("Erro na estrutura do EM, primeiro byte deve ser 0x00")

    # Passo 2: Separar maskedSeed e maskedDB
    masked_seed = encoded[1:hash_len+1]
    masked_db = encoded[hash_len+1:]


    # Passo 3: Gerar seedMask
    seed_mask = mgf1(masked_db, hash_len, hash_func)

    # Passo 4: Recuperar a semente
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))

    # Passo 5: Gerar dbMask
    db_mask = mgf1(seed, len(masked_db), hash_func)

    # Passo 6: Recuperar o bloco de dados DB
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))

    # Passo 7: Separar as partes de DB e verificar validade
    label_hash = hash_func(label).digest()
    if db[:hash_len] != label_hash:
        raise ValueError("Falha na decodificação OAEP, hash do rótulo não bate")

    # Encontrar o separador 0x01
    i = hash_len
    while i < len(db) and db[i] == 0:
        i += 1

    if i >= len(db) or db[i] != 1:
        raise ValueError("Formato inválido na decodificação OAEP, separador 0x01 ausente")

    # Retornar a mensagem decodificada
    return db[i+1:]


def Criptografia_rsa(mensagem, e, n):
    if isinstance(mensagem, int):
        mensagem = str(mensagem)
    n_length = (n.bit_length() + 7) // 8

     # Aplica OAEP encoding antes da exponenciação modular
    mensagem_codificada = oaep_encode(mensagem.encode(), n_length)

    # Converte os bytes da mensagem codificada para um número inteiro
    mensagem_codificada_int = int.from_bytes(mensagem_codificada, 'big')

    # Realiza a exponenciação modular (criptografia)
    mensagem_cifrada = pow(mensagem_codificada_int, e, n)

    return mensagem_cifrada

def Decriptografia_rsa(mensagem_cifrada, d, n):
    n_length = (n.bit_length() + 7) // 8  # Calcula o tamanho correto em bytes
    
    # Converte a mensagem criptografada para inteiro e aplica a exponenciação modular
    mensagem_dec = pow(mensagem_cifrada, d, n)
    
    # Converte o número inteiro de volta para bytes
    mensagem_dec_bytes = mensagem_dec.to_bytes(n_length, 'big')

    # Aplica a decodificação OAEP
    mensagem_decodificada = oaep_decode(mensagem_dec_bytes, n_length)
    return mensagem_decodificada.decode()

def Assinatura_Mensagem(mensagem, d, n):
    h = Hash(mensagem)
    assinatura = Criptografia_rsa(h, d, n)
    assinatura = formatacao_base64(assinatura)
    return assinatura

def Homologação_Assinatura(assinatura, mensagem, e, n):
    assinatura = reversao_base64(assinatura)
    h = Hash(mensagem)
    teste = Decriptografia_rsa(assinatura, e, n )
    if h == teste:
        return True
    else:
        return False

def formatacao_base64(assinatura):
    return base64.b64encode(assinatura.to_bytes((assinatura.bit_length() + 7) // 8, byteorder='big'))

def reversao_base64(texto_formatado):
    return int.from_bytes(base64.b64decode(texto_formatado), byteorder='big')

def extrair_assinatura(nome_arquivo):
    if not os.path.isfile(nome_arquivo):
        print("Arquivo não encontrado.")
        return None

    with open(nome_arquivo, "r", encoding="utf-8") as file:
        for line in file:
            if "Assinatura:" in line:
                return line.split("Assinatura: ", 1)[1].strip()
    
    print("Nenhuma assinatura encontrada no arquivo.")
    return None

def main():
    terminou = False
    verificador = True
    lista_assinaturas = {}
    lista_chaves_publicas = {}

    while not terminou:
        escolha = int(input("Digite 1 para fazer uma nova assinatura \nDigite 2 para homologar uma assinatura \nDigite 3 para encerrar o programa -> "))

        if escolha == 1:

            cpf = input("Qual cpf deseja vincular com a assinatura? ")
            documento = input("Insira o documento com a assinatura:")
            assinatura = extrair_assinatura(documento)

            while verificador:
                p = nextprime(10**308) 
                print(p)
                q = nextprime(10**308 + 2000)

                p_string = str(p)
                q_string = str(q)
                aux1 = p_string.strip()
                aux2 = q_string.strip()

                numero_teste = random.randint(10,100)

                teste_p = TesteMillerRabin(p, numero_teste)
                teste_q = TesteMillerRabin(q, numero_teste)
                print("p é primo?",teste_p)
                print("q é primo?", teste_q)
                verificador = False

                if not teste_p or len(aux1)<= 309:
                    if not teste_p:
                        print("O número P não é primo, insira outro P.")
                    if len(aux1)<= 309:
                        print("O número P tem menos do que 1024 bits, insira outro P")
                if not teste_q or len(aux2)<= 309:
                    if not teste_q:
                        print("O número Q não é primo, insira outro Q.")
                    if len(aux2)<= 309:
                        print("O número Q tem menos do que 1024 bits, insira outro Q.")
                else:
                    verificador = False

            chave_publica, chave_privada = Geracao_de_Chave(p,q)
            e = chave_publica[0]
            n = chave_publica[1]
            d = chave_privada[0]

            assinatura_digital = Assinatura_Mensagem(assinatura, d, n)
            
            lista_assinaturas[cpf] = assinatura_digital
            lista_chaves_publicas[cpf] = [e, n]

            print ("Assinatura realizada com sucesso!")
            print("Anote as seguintes chaves públicas geradas para uma eventual consulta:")
            print('Chave pública "e": ', e)
            print('Chave pública "n": ', n)
            

        elif escolha == 2:
            pessoa = input("Digite o cpf da pessoa cuja assinatura quer verificar: ")
            verificar = lista_assinaturas[pessoa]

            verificar_e, verificar_n = map(int, input('Digíte as chaves públicas "e" e "n", separadas por vírgula da assinatura que quer verificar: ').split(","))

            homologacao = Homologação_Assinatura(verificar, pessoa, verificar_e, verificar_n)

            if homologacao:
                print("Assinatura verificada com sucesso!")
            else:
                print("A assinatura não corresponde")
        elif escolha == 3:
            terminou = True

if __name__ == "__main__":
    main()
