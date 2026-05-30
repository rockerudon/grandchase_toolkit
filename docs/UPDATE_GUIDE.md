# Guia de Atualização — Como atualizar após patch do jogo

Quando o GrandChase atualiza, podem acontecer duas coisas:
1. **Offsets mudaram** — as funções crypto foram recompiladas para endereços diferentes
2. **Novas chaves AES** — novos KOMs com Algorithm 3 foram adicionados

Este guia explica como detectar e resolver ambos os casos.

---

## Checklist rápido após atualização

```
[ ] 1. Verificar se o jogo abre normalmente
[ ] 2. Rodar 02_find_offsets.py (encontrar novos offsets)
[ ] 3. Rodar 03_capture_keys.py --auto-merge (capturar novas chaves)
[ ] 4. Rodar pipeline.py --force (processar tudo com novos dados)
[ ] 5. Verificar output/decompiled/ — arquivos devem ser legíveis
```

---

## 1. Detectar se os offsets mudaram

Sinais de que os offsets mudaram:
- O script 03_capture_keys.py não captura nada (hooks não disparam)
- Falha de segmentação no Frida
- O jogo trava ao fazer attach

### 1.1 Tentar detecção automática

```bash
# Com o jogo aberto na tela de login:
python scripts/02_find_offsets.py
```

**O script usa 3 assinaturas de bytes para buscar as funções:**

| Função | Tamanho | Padrão Hex |
|--------|---------|-----------|
| CIPHER_INIT | 19 bytes | `4c89442418488954241048894c24084883ec28` |
| MODE_INIT | 24 bytes | `44894c24204c89442418488954241048894c24084883ec28` |
| BULK_DEC | 22 bytes | `4883ec38488b0144884c24204533c9ff50304883c438c3` |

**Regra de validação cruzada:**
`MODE_INIT = CIPHER_INIT + 0xC0` (isso nunca muda — são funções adjacentes no código)

**Interpretação dos resultados:**
```
[OK]        CIPHER_INIT = 1 match  → offset encontrado diretamente
[MÚLTIPLOS] CIPHER_INIT = 344 matches → usar MODE_INIT para disambiguar
[NÃO ENCONTRADO] → assinatura pode ter mudado (raro), ver seção 1.3
```

**Caso CIPHER_INIT tenha muitos matches**: O script automaticamente usa MODE_INIT
(que é mais única) e valida o par pelo gap de 0xC0. Isso foi o que aconteceu em
março 2026 (CIPHER_INIT tinha 344 matches, MODE_INIT tinha apenas 2).

### 1.2 Verificar o offsets.json após a atualização

O arquivo `keys/offsets.json` é atualizado automaticamente pelo script 02.
Verifique se os novos RVAs fazem sentido:

```json
{
    "aes": {
        "CIPHER_INIT": {"rva": "0x13d88d0"},
        "MODE_INIT":   {"rva": "0x13d8990"},
        "BULK_DEC":    {"rva": "0xba0460"}
    }
}
```

Validação manual: `MODE_INIT_rva - CIPHER_INIT_rva == 0xC0`
Exemplo: `0x13d8990 - 0x13d88d0 = 0xC0` ✓

### 1.3 Se as assinaturas não funcionarem (caso raro)

Se o jogo foi muito modificado e os padrões de bytes mudaram, use Ghidra:

1. **Fazer dump do executável** (o Themida descomprime em runtime):
   ```bash
   # Com jogo aberto:
   python scripts/01_dump_exe.py
   ```

2. **Abrir no Ghidra**:
   - File → Import → `output/grandchase_unpacked.bin`
   - Format: Raw Binary, Architecture: x86-64
   - O Ghidra vai analisar automaticamente

3. **Buscar CIPHER_INIT no Ghidra** (procurar por `AES_set_encrypt_key` ou similar):
   - Search → For Bytes: `4c 89 44 24 18`
   - Ou: Search → For String → "AES"
   - Navegar pelas referências cruzadas para encontrar as funções de inicialização

4. **Encontrar a assinatura única**: Uma vez encontrada a função, copie os primeiros
   20+ bytes e atualize `SIGNATURES` em `scripts/02_find_offsets.py`.

---

## 2. Capturar novas chaves AES (Algorithm 3)

### 2.1 Por que novas chaves aparecem?

Cada KOM com Algorithm 3 tem sua própria chave AES única, gerada por arquivo.
Quando novos KOMs são adicionados ao jogo, precisamos capturar as chaves deles.

### 2.2 Como saber se há chaves faltando?

```bash
python scripts/05_decrypt_all.py
```

Se aparecer `FAILED` para arquivos .lua específicos, as chaves AES deles não
estão no `algo3_keys.json`. Note quais KOMs estão falhando.

### 2.3 Processo de captura

```bash
# 1. Verificar/atualizar offsets primeiro (seção 1)
python scripts/02_find_offsets.py

# 2. Abrir o jogo e aguardar tela de login

# 3. Iniciar captura
python scripts/03_capture_keys.py --auto-merge

# 4. No jogo, navegar pelos menus que carregam os KOMs faltantes:
#    - Selecionar personagens (CharScript)
#    - Entrar em partidas PvP/PvE
#    - Abrir dungeons (Dungeon, Tower)
#    - Abrir todas as janelas de UI

# 5. Pressionar Ctrl+C quando terminar
```

O script exibe em tempo real os pares capturados com tag NOVO/EXISTENTE.

### 2.4 Verificar quais KOMs precisam de chave

Para um KOM específico que está falhando:
1. Extraia um arquivo dele: `python scripts/04_extract_koms.py --input arquivo.kom`
2. Tente decriptar: se falhar com "nenhuma chave funciona", é uma chave nova
3. Capture with o jogo carregando aquele conteúdo

### 2.5 Brute-force de chaves novas (se necessário)

Se você capturou muitos pares novos mas não sabe qual foi para qual KOM:

```bash
# Script de teste (no toolkit existente):
python _bruteforce_keys.py --target output/extracted/NomeDoCom/arquivo.lua
```

Ou manualmente em Python:
```python
from Crypto.Cipher import AES
import zlib, json

with open("keys/algo3_keys.json") as f:
    pairs = [(bytes.fromhex(p["key"]), bytes.fromhex(p["iv"])) for p in json.load(f)["pairs"]]

with open("arquivo_encriptado.lua", "rb") as f:
    data = f.read()

for key, iv in pairs:
    ecb = AES.new(key, AES.MODE_ECB)
    b0 = bytes(a ^ b for a, b in zip(ecb.decrypt(data[:16]), iv))
    if b0[:2] in [b'\x78\x9c', b'\x78\x01', b'\x78\x5e', b'\x78\xda']:
        full = AES.new(key, AES.MODE_CBC, iv).decrypt(data)
        try:
            zlib.decompress(full)
            print(f"ENCONTRADO: key={key.hex()} iv={iv.hex()}")
            break
        except:
            pass
```

---

## 3. Atualizar a tabela Blowfish (raramente necessário)

A tabela Blowfish (`algo2_table_full.bin`) é carregada do executável e raramente
muda entre atualizações. Se os algoritmos 2/3 pararem de funcionar:

```bash
# Com o jogo aberto:
# Usar o script de extração da tabela:
python CLASSIC\ EXTRACT\ TOOLKIT\frida\frida_extract_algo2_table.py

# Copiar a tabela extraída:
copy output_table.bin keys/algo2_table_full.bin
```

**Sinais de que a tabela mudou:**
- Algo2 falha em arquivos que antes funcionavam
- As chaves Blowfish presentes nos logs históricos não funcionam mais

---

## 4. Histórico de offsets por versão

| Data | Tamanho módulo | CIPHER_INIT | MODE_INIT | BULK_DEC |
|------|----------------|-------------|-----------|----------|
| Fev/2026 | 44.843.008 | 0x1384040 | 0x1384100 | 0xb7eed0 |
| Mar/2026 | 45.031.424 | 0x13d88d0 | 0x13d8990 | 0xba0460 |

O histórico completo está em `keys/offsets.json` → `history`.

---

## 5. Dicas e troubleshooting

### Frida não consegue fazer attach

```
[!] Failed to attach: unable to access process with pid X
```

Soluções:
1. Execute o Python com privilégios de administrador
2. Desative temporariamente o Windows Defender (real-time protection)
3. Adicione o Python ao exclusões do antivírus
4. Aguarde mais tempo o Themida desempacotar (aumente `--delay 15`)

### Hook não dispara (0 chaves capturadas)

1. Verifique se os offsets estão corretos (`02_find_offsets.py`)
2. Tente navegar pelo jogo — os hooks só disparam quando o jogo carrega KOMs
3. Verifique se o Python tem acesso ao processo (privilégios de admin)

### Decompilação falha para alguns arquivos

Isso é normal para arquivos com bytecode muito complexo.
O toolkit salva o bytecode raw como `.kl` para inspeção manual.
Tente o decompilador com `--force` para reprocessar com a última versão.

### STG files não decriptados

Os arquivos STG precisam de chaves específicas capturadas via `frida_stg_keycapture.js`.
As chaves STG são Blowfish de 32 bytes Por arquivo. Se não decriptarem:
1. Usando `stg_decrypt/frida_stg_keycapture.py` capture as chaves
2. Salve o resultado como `keys/stg_keys.json`
3. Rode `05_decrypt_all.py` novamente

### `algo3_keys.json` — Par errado (falso positivo)

Raramente, dois KOMs podem ter o magic zlib coincidente. Se um arquivo decriptar
mas o resultado não for Lua válido:
1. Remova o par suspeito do `algo3_keys.json`
2. Recapture a chave com `03_capture_keys.py` enquanto carrega especificamente aquele KOM
