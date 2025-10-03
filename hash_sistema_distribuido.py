import hashlib
import random
import string
import math

# Parâmetros
NUM_NOS = 1000
NUM_DADOS = 5000
algoritmos = ["MD5", "SHA-1", "SHA-256", "SHA3-256"]

random.seed(42)

# Hashes com suporte a colisões forçadas
forced_hashes = {alg: {} for alg in algoritmos}

def hash_md5(data: str) -> str:
    return forced_hashes["MD5"].get(data, hashlib.md5(data.encode()).hexdigest())

def hash_sha1(data: str) -> str:
    return forced_hashes["SHA-1"].get(data, hashlib.sha1(data.encode()).hexdigest())

def hash_sha256(data: str) -> str:
    return forced_hashes["SHA-256"].get(data, hashlib.sha256(data.encode()).hexdigest())

def hash_sha3_256(data: str) -> str:
    return forced_hashes["SHA3-256"].get(data, hashlib.sha3_256(data.encode()).hexdigest())

# Estrutura de nós
nós_alg = {alg: [{} for _ in range(NUM_NOS)] for alg in algoritmos}
PRIME = 15485863

def escolher_no(chave: str, alg: str) -> int:
    h_hex = {
        "MD5": hash_md5(chave),
        "SHA-1": hash_sha1(chave),
        "SHA-256": hash_sha256(chave),
        "SHA3-256": hash_sha3_256(chave)
    }[alg]
    h = int(h_hex, 16)
    mixed = (h % PRIME) ^ ((h >> 32) % PRIME)
    return mixed % NUM_NOS

def armazenar_dado(chave: str, valor: str):
    for alg in algoritmos:
        no = escolher_no(chave, alg)
        nós_alg[alg][no][chave] = valor

def verificar_integridade(chave: str, valor: str) -> dict:
    resultados = {}
    for alg in algoritmos:
        no = escolher_no(chave, alg)
        valor_no = nós_alg[alg][no].get(chave)
        if valor_no is None:
            resultados[alg] = False
        else:
            hash_func = {
                "MD5": hash_md5,
                "SHA-1": hash_sha1,
                "SHA-256": hash_sha256,
                "SHA3-256": hash_sha3_256
            }[alg]
            resultados[alg] = hash_func(valor_no) == hash_func(valor)
    return resultados

# Geração de dados
def gerar_dado(k=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=k))

dados = {f"user{i}": gerar_dado() for i in range(1, NUM_DADOS+1)}

for chave, valor in dados.items():
    armazenar_dado(chave, valor)

# Dados alterados com as colisões
dados_alterados = {k: gerar_dado() for i, (k, v) in enumerate(dados.items()) if i % 20 == 0}

dados["user_md5_orig"] = "AAAA"
dados_alterados["user_md5_orig"] = "BBBB"
dados["user_sha1_orig"] = "CCCC"
dados_alterados["user_sha1_orig"] = "DDDD"

forced_hashes["MD5"]["AAAA"] = forced_hashes["MD5"]["BBBB"] = "deadbeefdeadbeefdeadbeefdeadbeef"
forced_hashes["SHA-1"]["CCCC"] = forced_hashes["SHA-1"]["DDDD"] = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"

for chave in ("user_md5_orig", "user_sha1_orig"):
    armazenar_dado(chave, dados[chave])

# Função de entropia
def entropia(contagem):
    total = sum(contagem)
    if total == 0:
        return 0.0
    probs = [c/total for c in contagem if c > 0]
    return -sum(p*math.log2(p) for p in probs)

# Análise comparativa final
integridade_original = {alg: 0 for alg in algoritmos}
for chave, valor in dados.items():
    resultados = verificar_integridade(chave, valor)
    for alg, ok in resultados.items():
        if ok:
            integridade_original[alg] += 1

integridade_alterada_true = {alg: 0 for alg in algoritmos}
for chave, novo_valor in dados_alterados.items():
    resultados = verificar_integridade(chave, novo_valor)
    for alg, v in resultados.items():
        if v:
            integridade_alterada_true[alg] += 1

total_alterados = len(dados_alterados)
detecções = {alg: total_alterados - integridade_alterada_true[alg] for alg in algoritmos}

distribuicao = {}
for alg in algoritmos:
    contagem = [len(nó) for nó in nós_alg[alg]]
    distribuicao[alg] = contagem

print("\n=== Análise Comparativa Final ===")
print("\nIntegridade - dados originais")
for alg, acertos in integridade_original.items():
    print(f"{alg}: {acertos}/{NUM_DADOS + 2}")

print("\nIntegridade - dados alterados / falhas proposital")
for alg in algoritmos:
    print(f"{alg}: detectou alterações em {detecções[alg]}/{total_alterados} (falhas não detectadas: {integridade_alterada_true[alg]})")

print("\nDistribuição de dados nos nós (entropia)")
for alg, contagem in distribuicao.items():
    e = entropia(contagem)
    media = sum(contagem)/len(contagem)
    variancia = sum((c-media)**2 for c in contagem)/len(contagem)
    desv = math.sqrt(variancia)
    print(f"{alg}: entropia = {e:.4f} | média = {media:.3f} | std = {desv:.3f}")

print("\nCriptografia - colisões (simuladas)")
hashes_colisao = {
    "MD5": (hash_md5("AAAA"), hash_md5("BBBB")),
    "SHA-1": (hash_sha1("CCCC"), hash_sha1("DDDD")),
    "SHA-256": (hash_sha256("AAAA"), hash_sha256("BBBB")),
    "SHA3-256": (hash_sha3_256("AAAA"), hash_sha3_256("BBBB"))
}
for alg, (h1, h2) in hashes_colisao.items():
    if h1 == h2:
        print(f"{alg}: FALHOU (colisão simulada).")
    else:
        print(f"{alg}: SEGURO (para o par testado).")