import random
import hashlib
import base64

def mdc(a, b):
    while b:
        a, b = b, a % b
    return a

def PseudoPrimoForte( n, b ):
    
    # primeiro escrevemos n - 1 = 2^k*q
    q = n-1
    k = 0
    while q % 2 == 0:
        q = q//2
        k = k+1
    
    # se b^q é congruente com 1 mod n então True
    r = pow( b, q, n )
    if r == 1:
        return True
    
    # se existe algum i entre 0 e k-1 tal que 
    # b^(2^iq) é congruente com -1 mod n então true
    for i in range( 0, k ):
        if r == n-1:
            return True
        r = r*r % n
    
    # caso contrário devolva false
    return False

def TesteMillerRabin( n, k ):
# k é um número de bases aleatórias
        
    for i in range( k ):
        b = random.randint( 2, n-1 )
        if not PseudoPrimoForte( n, b ):
            return False
    #Provávelmente retorna um primo
    return True

#FAZER OS CONDICIONAIS FUNCIONAREM
def Geracao_de_Chave(p,q):
    n = p * q

    print('O valor de "n" é: ',n)

    phi = (p - 1) * (q - 1)

    print('O valor de "phi" é: ',phi)

    e = int(input('Escolha o "e" tal que o mdc entre "e" e "phi" seja = 1 e "e" seja menor que "phi": '))

    #calculo de inverso modular de "e" módulo "n"
    d = pow(e, -1, phi)

    chave_publica = [e,n]
    chave_privada = [d,n]

    return chave_publica, chave_privada

def Hash(mensagem):
    h = hashlib.sha256(mensagem.encode()).hexdigest()
    return h

def Criptografia_rsa(mensagem, e, n ):
    C = (mensagem ** e) % n
    return C

def Decriptografia_rsa(c, d, n):
    mensagem = (c ** d) % n
    return mensagem

def Assinatura_Mensagem(mensagem, d, n):
    h = Hash(mensagem)
    assinatura = Criptografia_rsa(h, d, n)
    return assinatura

def formatacao_base64(assinatura):
    assinatura_formatada = base64.b64encode(assinatura)
    return assinatura_formatada

def reversao_base64(texto_formatado):
    reversao = base64.b64decode(texto_formatado)
    return reversao

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

    print(Criptografia_rsa(7,e,n))
    c = Criptografia_rsa(7,e,n)
    print(Decriptografia_rsa(c,d,n))

    M = input("Digite a mensagem:")
    hash_mensagem = Hash(M)

    

if __name__ == "__main__":
    main()