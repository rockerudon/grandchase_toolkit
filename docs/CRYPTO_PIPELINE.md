# Pipeline de Criptografia — GrandChase Epic

Documentação técnica completa dos pipelines de encriptação usados no GrandChase V1.0 (Epic).

---

## Visão Geral

```
KOM File
    ↓
[Header XML] ← XOR cíclico (known-plaintext '<?xml versio')
    ↓
[Entry Blobs]
    ├── AlgoType 0 → zlib → Original
    ├── AlgoType 2 → Blowfish-ECB → zlib → Original
    └── AlgoType 3 → AES-256-CBC → zlib → Blowfish-ECB → KL Bytecode
                         ↑                      ↑
                   key/iv capturados        chave derivada
                   via Frida               da tabela binária
```

---

## Algorithm 0 — Apenas zlib

**Entrada:** blob comprimido  
**Saída:** dados originais

```python
import zlib
data = zlib.decompress(blob)
```

**Distribuição:** ~7,6% dos arquivos (principalmente recursos não-script)

---

## Algorithm 2 — Blowfish-ECB + zlib

**Distribuição:** ~92,4% dos arquivos Lua/STG  
**Chave:** 32 bytes derivados de tabela estática  

### Pipeline completo:

```
blob_encriptado
    ↓ Blowfish-ECB decrypt(key_32B)
blob_comprimido_zlib
    ↓ zlib.decompress()
dados_originais (KL bytecode ou texto)
```

### Derivação da chave Blowfish:

```python
import struct, hashlib

# 1. Ler entrada da tabela (40 bytes: 5 × int64 little-endian)
entry_bytes = table_data[index * 40 : (index + 1) * 40]
vals = struct.unpack('<5q', entry_bytes)

# 2. Somar os 5 valores
total = sum(vals)
if total < 0:
    total &= 0xFFFFFFFFFFFFFFFF   # Tratar como uint64

# 3. Converter para string ASCII e hashear com SHA-256
#    !! CRUCIAL: usar str(), não to_bytes() !!
key = hashlib.sha256(str(total).encode('ascii')).digest()  # 32 bytes
```

**Tabela:** `keys/algo2_table_full.bin`
- 13.790 entradas × 40 bytes = 551.600 bytes
- Reside no .data do GrandChase.exe em RVA 0x1dd3de0

### Decriptação Blowfish:

```python
from Crypto.Cipher import Blowfish

# Blocos de 8 bytes (Blowfish processa apenas múltiplos de 8)
aligned = (len(blob) // 8) * 8
tail = blob[aligned:]  # bytes finais (0-7) não são encriptados

cipher = Blowfish.new(key, Blowfish.MODE_ECB)
decrypted = cipher.decrypt(blob[:aligned]) + tail
```

### Descoberta do índice (brute-force):

```python
import zlib
from Crypto.Cipher import Blowfish

def find_bf_key(blob, keys):
    aligned = (len(blob) // 8) * 8
    tail = blob[aligned:]
    
    for idx, key in enumerate(keys[1:], 1):  # Índice 0 = all-zeros, pular
        try:
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
            dec = cipher.decrypt(blob[:aligned]) + tail
            zlib.decompress(dec)  # Sucesso = chave correta
            return idx, dec
        except Exception:
            continue
    return -1, None
```

**Otimização:** Cache por KOM. Arquivos do mesmo KOM geralmente usam o mesmo
índice. Testar primeiro os índices recentes reduz o tempo de ~100ms para ~1ms/arquivo.

---

## Algorithm 3 — AES-256-CBC + zlib + Blowfish-ECB

**Distribuição:** ~7,6% dos arquivos Lua (os mais recentes)  
**Pipeline:**

```
blob_encriptado_aes (tamanho múltiplo de 16)
    ↓ AES-256-CBC.decrypt(key=32B, iv=16B)
blob_zlib_encriptado
    ↓ zlib.decompress()
blob_encriptado_blowfish
    ↓ Blowfish-ECB.decrypt(key=32B)
KL bytecode
```

### Passo 1: AES-256-CBC

```python
from Crypto.Cipher import AES
import zlib

def decrypt_algo3_aes(blob, key, iv):
    # Quick check: testar apenas primeiro bloco antes de decriptar tudo
    ecb = AES.new(key, AES.MODE_ECB)
    dec_block = ecb.decrypt(blob[:16])
    # CBC: plaintext[0] = AES_dec(cipher[0]) XOR iv
    plain0 = bytes(a ^ b for a, b in zip(dec_block, iv))
    
    # Verificar magic zlib no primeiro byte
    if plain0[:2] not in [b'\x78\x9c', b'\x78\x01', b'\x78\x5e', b'\x78\xda']:
        return None  # Chave errada, pular
    
    # Decriptar tudo
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(blob)
```

**Chaves e IVs:** Únicos por KOM, armazenados em `keys/algo3_keys.json`.

Para descobrir qual par funciona para um dado KOM:
- Tentar todos os 52 pares (quick-check no primeiro bloco)
- O correto produz magic zlib válido + zlib.decompress() sem erro

### Passo 2: Passo Blowfish idêntico ao Algo2

Após o zlib, o resultado é outro blob encriptado com Blowfish.
Derivação e brute-force idênticos ao Algorithm 2.

### Como as chaves AES são capturadas

O GrandChase inicializa AES com 3 chamadas de função:

```
CIPHER_INIT(ctx, key_ptr, key_len=32, ...)     ← Captura chave 32 bytes
MODE_INIT(ctx, ?, iv_ptr, dir=0, ...)          ← Captura IV 16 bytes (apenas decrypt)
BULK_DEC(ctx, in, out, n_blocks, ...)          ← Executa decriptação
```

**Hooks Frida:**

```javascript
// CIPHER_INIT — captura chave
Interceptor.attach(base.add(CI_RVA), {
    onEnter: function(args) {
        var key = args[1].readByteArray(32);
        send({type: 'cipher_init', key: Array.from(new Uint8Array(key)).map(b => b.toString(16).padStart(2,'0')).join('')});
    }
});

// MODE_INIT — captura IV (apenas decrypt: dir==0)
Interceptor.attach(base.add(MI_RVA), {
    onEnter: function(args) {
        if (args[3].toInt32() !== 0) return;  // Pular encrypt
        var iv = args[2].readByteArray(16);
        send({type: 'mode_init', iv: Array.from(new Uint8Array(iv)).map(b => b.toString(16).padStart(2,'0')).join('')});
    }
});
```

**Pareamento key↔IV:** Um contador global `N` é incrementado a cada CIPHER_INIT.
O MODE_INIT com o mesmo `N` contém o IV correspondente.

---

## STG — Blowfish-ECB (32 bytes)

Arquivos `.stg` são texto UTF-16-LE encriptado com Blowfish-ECB.

```
arquivo_stg_encriptado
    ↓ Blowfish-ECB.decrypt(key=32B)
UTF-16-LE: FF FE [texto...]
```

**Chave:** 32 bytes por arquivo, capturada via `stg_decrypt/frida_stg_keycapture.py`.

**Validação:**
```python
from Crypto.Cipher import Blowfish
def is_valid_stg(data, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    dec = cipher.decrypt(data[:8])
    return dec[:2] == b'\xff\xfe'  # UTF-16-LE BOM
```

**Cross-key:** Como o jogo usa ~299 chaves únicas para todos os recursos,
uma chave capturada de um .lua pode funcionar para um .stg não capturado.
O script 05_decrypt_all.py tenta todas as chaves disponíveis.

---

## Decompilador LJD — KL Bytecode

O GrandChase usa LuaJIT modificado com bytecode "KL" (custom).

**Diferenças em relação ao LuaJIT padrão:**
- Magic: `\x1bKL\x84` (em vez de `\x1bLJ\x01`)
- 97 opcodes remapeados (tabela de tradução hardcoded no parser)

**Pipeline de decompilação (LJD):**
```
KL bytecode
    ↓ parser.parse() → header + prototype
    ↓ ast.builder.build() → AST
    ↓ [opcional] validator.validate(warped=True)
    ↓ mutator.pre_pass()
    ↓ [opcional] locals.mark_locals() → eliminate_temporary()
    ↓ [opcional] unwarper.unwarp()
    ↓ [opcional] locals.mark_local_definitions()
    ↓ [opcional] mutator.primary_pass()
    ↓ slotrenamer.rename_slots()
    ↓ lua.writer.write()
    ↓ Código Lua legível
```

### API correta do LJD:

```python
# !! Usar eliminate_temporary, NÃO mark_slots (não existe) !!
import ljd.ast.slotworks
ljd.ast.slotworks.eliminate_temporary(ast)      # Correto

# !! Usar mark_local_definitions, NÃO mark_definitions !!
import ljd.ast.locals
ljd.ast.locals.mark_local_definitions(ast)      # Correto
```

**3 níveis de fallback:**
- **L0** (completo): Inclui unwarper — melhor qualidade de código
- **L1** (sem unwarper): Skipa `unwarper.unwarp()` — funciona para 90%+ dos arquivos
- **L2** (mínimo): Apenas mutator — fallback de último recurso

A maioria dos arquivos decompila em L1 (o unwarper falha em alguns patterns).

---

## Resumo das chaves/tabelas

| Arquivo | Descrição | Tamanho |
|---------|-----------|---------|
| `keys/algo3_keys.json` | 52 pares AES (key+iv) para Algorithm 3 | ~8KB |
| `keys/algo2_table_full.bin` | Tabela BF completa (13.790 entradas) | 551KB |
| `keys/algo2_table.bin` | Tabela BF parcial (984 entradas, legada) | 39KB |
| `keys/offsets.json` | RVAs das funções crypto com assinaturas | ~3KB |
| `keys/stg_keys.json` | Chaves BF para STG (capturadas separately) | variável |
