# Formato KOM — GrandChase V1.0 (Epic)

KOM é o formato de arquivo de dados do GrandChase. É essencialmente um container
tipo "zip" que agrupa múltiplos arquivos em um único `.kom`.

## Localização dos arquivos

```
C:\Program Files\Epic Games\GrandChaseuVQ2P\
├── Resource\      ← Scripts Lua, texturas, UI
├── Character\     ← Animações, modelos de personagens
├── Stage\         ← Mapas, scripts de cenários
└── Sound\         ← Áudio, músicas
```

Cada pasta contém dezenas de arquivos `.kom`. Exemplos:
- `Char_Script.kom` — Scripts Lua dos personagens
- `map.kom` — Mapas de stage (contém .stg: arquivos de dados do estágio)
---

## Estrutura do arquivo KOM V1.0

```
Offset  Tamanho  Significado
------  -------  -----------
0       52       Magic word: "KOG GC TEAM MASSFILE V1.0\x00..." (padded)
52      4        entry_count (número de arquivos no KOM)
56      4        compressed_key_index (índice da chave de encriptação)
60      4        filetime (timestamp DOS)
64      4        unk_v10  (desconhecido, ignorado)
68      4        adler32_header (checksum do header XML)
72      4        headersize (tamanho do header XML encriptado)
76      ...      Header XML (XOR-encriptado, tamanho = headersize)
76+hs   ...      Payload (blobs concatenados)
```

**Total do preâmbulo antes do payload:** `76 + headersize` bytes.

---

## Header XML

O header XML contém metadados de cada arquivo no KOM.
Ele é XOR-encriptado com uma chave de 12 bytes derivada por known-plaintext:

```python
# O header começa sempre com '<?xml versio' (12 bytes fixos)
known = b'<?xml versio'
key   = bytes(hdr_enc[i] ^ known[i] for i in range(12))
# Aplicar XOR cíclico com a chave de 12 bytes
header_xml = bytes(hdr_enc[i] ^ key[i % 12] for i in range(len(hdr_enc)))
```

### Exemplo de header XML decriptado:

```xml
<?xml version="1.0" encoding="EUC-KR"?>
<MassFile>
  <File Name="Char_Script/Arme.lua"
        FileSize="15240"
        CompSize="4827"
        Checksum="a1b2c3d4"
        AlgorithmType="3" />
  <File Name="Char_Script/Elesis.lua"
        FileSize="12800"
        CompSize="3950"
        Checksum="e5f6a7b8"
        AlgorithmType="2" />
  ...
</MassFile>
```

**Campos importantes:**
- `Name` — nome do arquivo (path relativo)
- `FileSize` — tamanho original descomprimido
- `CompSize` — tamanho do blob no payload
- `AlgorithmType` — algoritmo de encriptação (0, 2 ou 3)

---

## Algoritmos de encriptação dos blobs

### AlgorithmType="0" — Apenas zlib

```
blob → zlib.decompress() → dados originais
```

### AlgorithmType="2" — Blowfish-ECB + zlib

```
blob → Blowfish-ECB decrypt → zlib.decompress() → dados originais
```

Derivação da chave Blowfish:
```python
import struct, hashlib

# Ler entrada da tabela (40 bytes = 5 × int64 little-endian)
vals = struct.unpack_from('<5q', table_data, index * 40)
total = sum(vals)
if total < 0:
    total &= 0xFFFFFFFFFFFFFFFF

# !! IMPORTANTE: usar str em ASCII, não to_bytes !!
key = hashlib.sha256(str(total).encode('ascii')).digest()  # 32 bytes
```

**A tabela está em:** `keys/algo2_table_full.bin` (13.790 entradas)

O índice correto é encontrado por brute-force: tentar cada entrada até
a decriptação BF + zlib.decompress() funcionar. Cache per-KOM acelera muito
(arquivos do mesmo KOM geralmente usam o mesmo índice).

### AlgorithmType="3" — AES-256-CBC + zlib + Blowfish-ECB

```
blob → AES-256-CBC decrypt(key, iv) → zlib.decompress() → Blowfish-ECB decrypt → KL bytecode
```

A chave AES e o IV são únicos por KOM e são capturados em runtime via Frida.
Armazenados em `keys/algo3_keys.json`.

Após o zlib, o resultado ainda está encriptado com Blowfish (mesma derivação do Algo2).
O índice BF é encontrado da mesma forma (brute-force da tabela).

---

## Tipos de arquivos dentro dos KOMs

| Extensão | Tipo | Descrição |
|----------|------|-----------|
| `.lua` | Script Lua (bytecode KL) | Scripts de jogo |
| `.stg` | Stage data (UTF-16-LE) | Dados de estágio |
| `.kstg` | Stage data binário | Mapas binários |
| `.dds` | Textura DirectDraw Surface | Imagens |
| `.wav` | Áudio PCM | Sons |
| `.xml` | XML | Configurações |
| `.bin` | Binário genérico | Vários |

---

## Bytecode KL (Lua customizado)

Os arquivos `.lua` dentro dos KOMs são bytecode **KL**, não Lua padrão.
O GrandChase usa uma versão modificada do LuaJIT com:
- Magic header: `\x1bKL\x84` (em vez de `\x1bLJ`)
- Remapeamento de 97 opcodes

**Identificação:**
```python
KL_MAGIC = b'\x1bKL\x84'
LJ_MAGIC = b'\x1bLJ'

if data[:4] == KL_MAGIC:
    print("KL bytecode (GrandChase)")
elif data[:3] == LJ_MAGIC:  
    print("LuaJIT padrão")
```

O decompilador LJD (em `decompiler/ljd_decompiler/`) faz o remapeamento
automaticamente e gera código Lua legível.

---

## Arquivos STG

Arquivos `.stg` são dados de stage em UTF-16-LE (com BOM `\xff\xfe`).
Ficam em `Stage/string/` dentro dos KOMs de stage.

Encriptação: Blowfish-ECB com chave de 32 bytes por arquivo.
As chaves STG são capturadas via `stg_decrypt/frida_stg_keycapture.py`.

Após decriptação: texto UTF-16-LE → converter para UTF-8 para legibilidade.

---

## Outras versões KOM (legado)

| Versão | Magic | Descrição |
|--------|-------|-----------|
| V0.1/V0.2 | `KOG GC TEAM MASSFILE V.0.1` | Sem encriptação |
| V0.3 | V.0.3 | XOR simples |
| V0.4 | V.0.4 | Blowfish-ECB com SHA1 na chave |
| V0.5 | V.0.5 | XOR com ulD (24 bytes) |
| V0.6 | V.0.6 | AES-128-CBC |
| **V1.0** | V.1.0 | **Versão atual (Epic)** — AES-256-CBC + BF |
| GCM V0.6 | `GCM GC TEAM MASSFILE V.0.6` | Servidor Privado |

O `extractor/kom_crypto.py` suporta todas as versões.
