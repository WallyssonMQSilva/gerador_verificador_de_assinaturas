import random
import hashlib
import base64

def mdc(a, b):
    while b:
        a, b = b, a % b
    return a

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
    e = int(input('Escolha o "e" tal que o mdc entre "e" e "phi" seja = 1 e "e" seja menor que "phi": '))
    d = pow(e, -1, phi)
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
    ps = b'\x00' * (max_msg_len - len(message))
    db = hash_func(label).digest() + ps + b'\x01' + message
    seed = random.getrandbits(hash_len * 8).to_bytes(hash_len, byteorder='big')
    db_mask = mgf1(seed, len(db), hash_func)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    seed_mask = mgf1(masked_db, hash_len, hash_func)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))
    return b'\x00' + masked_seed + masked_db

def oaep_decode(encoded, n_length, label=b"", hash_func=hashlib.sha256):
    hash_len = hash_func().digest_size
    masked_seed = encoded[1:hash_len+1]
    masked_db = encoded[hash_len+1:]
    seed_mask = mgf1(masked_db, hash_len, hash_func)
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))
    db_mask = mgf1(seed, len(masked_db), hash_func)
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))
    label_hash = hash_func(label).digest()
    if db[:hash_len] != label_hash:
        raise ValueError("Falha na decodificação OAEP")
    i = hash_len
    while i < len(db) and db[i] == 0:
        i += 1
    if db[i] != 1:
        raise ValueError("Formato inválido na decodificação OAEP")
    return db[i+1:]

def Criptografia_rsa(mensagem, e, n):
    if isinstance(mensagem, int):
        mensagem = str(mensagem)
    n_length = (n.bit_length() + 7) // 8
    mensagem_codificada = oaep_encode(mensagem.encode(), n_length)
    mensagem_int = int.from_bytes(mensagem_codificada, byteorder='big')
    return pow(mensagem_int, e, n)

def Decriptografia_rsa(c, d, n):
    n_length = (n.bit_length() + 7) // 8
    mensagem_dec_int = pow(c, d, n)
    mensagem_dec_bytes = mensagem_dec_int.to_bytes(n_length, byteorder='big')
    return oaep_decode(mensagem_dec_bytes, n_length).decode()

def Assinatura_Mensagem(mensagem, d, n):
    h = Hash(mensagem)
    assinatura = Criptografia_rsa(h, d, n)
    return assinatura

def formatacao_base64(assinatura):
    return base64.b64encode(assinatura.to_bytes((assinatura.bit_length() + 7) // 8, byteorder='big'))

def reversao_base64(texto_formatado):
    return int.from_bytes(base64.b64decode(texto_formatado), byteorder='big')

def main():
    verificador = True
    while verificador:
        p = int(input('Escolha o primeiro primo "p" que tenha ao menos 1024 bits(309 dígitos): '))
        q = int(input('Escolha o segundo primo "q" que tenha ao menos 1024 bits(309 dígitos): '))

        p_string = str(p)
        q_string = str(q)
        aux1 = p_string.strip()
        aux2 = q_string.strip()

        numero_teste = random.randint(10,100)

        teste_p = TesteMillerRabin(p, numero_teste)
        teste_q = TesteMillerRabin(q, numero_teste)
        verificador = False

        #if not teste_p or len(aux1)<= 309:
         #   if not teste_p:
          #      print("O número P não é primo, insira outro P.")
           # if len(aux1)<= 309:
            #    print("O número P tem menos do que 1024 bits, insira outro P")
        #if not teste_q or len(aux2)<= 309:
         #   if not teste_q:
          #      print("O número Q não é primo, insira outro Q.")
           # if len(aux2)<= 309:
            #    print("O número Q tem menos do que 1024 bits, insira outro Q.")
        #else:
         #   verificador = False
    chave_publica, chave_privada = Geracao_de_Chave(p,q)
    e = chave_publica[0]
    n = chave_publica[1]
    d = chave_privada[0]

    mensagem = input("Digite a mensagem: ")
    criptografado = Criptografia_rsa(mensagem, e, n)
    print("Mensagem criptografada:", criptografado)
    descriptografado = Decriptografia_rsa(criptografado, d, n)
    print("Mensagem descriptografada:", descriptografado)
    assinatura = Assinatura_Mensagem(mensagem, d, n)
    assinatura_formatada = formatacao_base64(assinatura)
    print("Assinatura formatada em Base64:", assinatura_formatada.decode())
    assinatura_revertida = reversao_base64(assinatura_formatada)
    print("Assinatura revertida:", assinatura_revertida)

    

if __name__ == "__main__":
    main()
