# kom_crypto.py
# Implementação para DDTank Classic (Epic Games)
# Compatível: KOG V1.0 (ver_num==10)
#
import os
import struct
import zlib
import time
from xml.dom.minidom import parseString

# Tentar importar Crypto (usado em V4)
try:
    from Crypto.Cipher import Blowfish
    from Crypto.Hash import SHA1
    CRYPTO_AVAILABLE = True
except ImportError:
    Blowfish = None
    SHA1 = None
    CRYPTO_AVAILABLE = False
    print("AVISO: pycryptodome não instalado. Arquivos KOM versão 4 não poderão ser descriptografados.")
    print("Instale com: pip install pycryptodome")

HEADER_MAGIC = b"KOG GC TEAM MASSFILE "
HEADER_SIGNATURES = (
    (b"KOG GC TEAM MASSFILE V.", "KOG"),
)
HEADEROFFSET = 72  # 52 (magic) + 4 (size) + 4 (compressed) + 4 (filetime) + 4 (adler32) + 4 (headersize)
# KOG V1.0 (ver_num==10) tem um uint32 extra no cabeçalho antes do header XML
# (filetime, unk_v10, adler32, headersize) -> offset base vira 76.
V10_HEADEROFFSET = 76

# Chave XOR repetitiva observada em KOG V1.0 (Epic client) para decodificar o header XML.
# Nota: pode variar por build/client; mantemos como tentativa best-effort.
V10_HEADER_XOR_KEY = bytes.fromhex("6cfaee32e4f09efd8d02b6db")


def _find_massfile_magic_offset(blob: bytes):
    """Retorna o primeiro offset com assinatura conhecida de MASSFILE."""
    found = []
    for signature, _ in HEADER_SIGNATURES:
        idx = blob.find(signature)
        if idx != -1:
            found.append(idx)
    if not found:
        return -1
    return min(found)


def _parse_version_and_flavor_from_magicblock(magicblock: bytes):
    """
    Detecta assinatura KOG e extrai versao V.x.y.
    Retorna (major, minor, ver_num, flavor) ou None.
    """
    try:
        import re

        for signature, flavor in HEADER_SIGNATURES:
            idx = magicblock.find(signature)
            if idx == -1:
                continue
            after = magicblock[idx + len(signature):]
            m = re.search(rb"(\d+)\.(\d+)", after)
            if not m:
                continue
            a = int(m.group(1))
            b = int(m.group(2))
            vernum = a * 10 + b
            return a, b, vernum, flavor
        return None
    except Exception:
        return None


def _xor_cycle(data: bytes, key: bytes) -> bytes:
    """Aplica XOR cíclico com a chave fornecida."""
    if not data or not key:
        return data
    out = bytearray(data)
    klen = len(key)
    for i in range(len(out)):
        out[i] ^= key[i % klen]
    return bytes(out)


def _blowfish_decrypt_with_sha1_key(data: bytes, seed_int64: int) -> bytes:
    """
    Replica DecryptHeader do C++:
    - chave = SHA1(str(seed_int64)) (20 bytes)
    - usar Blowfish(sha1key, 20) em modo ECB
    """
    if not CRYPTO_AVAILABLE:
        raise ImportError("pycryptodome não está instalado. Instale com: pip install pycryptodome")
    keystr = str(seed_int64).encode("ascii")
    h = SHA1.new()
    h.update(keystr)
    sha1key = h.digest()  # 20 bytes
    cipher = Blowfish.new(sha1key, Blowfish.MODE_ECB)
    # Blowfish precisa de múltiplos de 8
    chunk = 8
    out = bytearray()
    nblocks = len(data) // chunk
    if nblocks > 0:
        out.extend(cipher.decrypt(data[:nblocks * chunk]))
    if len(data) % chunk:
        out.extend(data[nblocks * chunk:])  # manter o resto cru
    return bytes(out)


def _adler32(data: bytes) -> int:
    """Calcula Adler32 checksum"""
    return zlib.adler32(data) & 0xFFFFFFFF


def _xor_v10_header(data: bytes) -> bytes:
    """Aplica XOR cíclico no header KOG V1.0 (ver_num==10) para revelar XML.
    Deriva a chave XOR de 12 bytes automaticamente usando known-plaintext
    (todo header XML começa com '<?xml versio')."""
    if len(data) < 12:
        return _xor_cycle(data, V10_HEADER_XOR_KEY)
    known = b'<?xml versio'  # primeiros 12 bytes de qualquer header XML
    key = bytes(a ^ b for a, b in zip(data[:12], known))
    return _xor_cycle(data, key)


def _guess_entry_extension(data: bytes) -> str:
    """Heurística simples para sugerir extensão com base na assinatura."""
    if not data:
        return ".bin"
    if data.startswith(b"DDS "):
        return ".dds"
    if data.startswith(b"RIFF"):
        return ".wav"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith((b"<?xml", b"<")):
        return ".xml"
    if data.startswith(b"PK\x03\x04"):
        return ".zip"
    # Texto simples (ex.: scripts/lists)
    sample = data[:256]
    text_ratio = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127) / max(1, len(sample))
    if text_ratio > 0.90:
        return ".txt"
    return ".bin"


class KomArchive:
    # Chave padrão do jogo (conforme código C++)
    DEFAULT_V4_KEY = 1846201835
    
    def __init__(self, keymap: dict = None, debug: bool = False, use_default_key: bool = True):
        """
        keymap: dict mapping uint32 (compressed key) -> int64 seed
        debug: imprime passos/offsets
        use_default_key: se True, usa chave padrão 1846201835 quando keymap não tem a chave
        """
        self.entries = []
        self.version = None
        self._raw_header = None
        self.encryption_key_index = None
        self.keymap = keymap or {}
        self.debug = bool(debug)
        self.use_default_key = use_default_key
        self.filetime = 0
        self.adler32_header = 0
        self.headersize = 0
        self.massfile_flavor = "KOG"
        
        # Adicionar chave padrão ao keymap se use_default_key for True
        if self.use_default_key:
            # A chave padrão é mapeada para vários compressed keys comuns
            # Conforme o código C++, a chave padrão é 1846201835
            # O compressed key é calculado como adler32 da string do seed
            key_str = str(self.DEFAULT_V4_KEY)
            calculated_adler = _adler32(key_str.encode("ascii"))
            self._d(f"Chave padrão {self.DEFAULT_V4_KEY} -> adler32: 0x{calculated_adler:08X}")
            
            # Mapear para compressed keys comuns (incluindo o calculado)
            common_keys = [calculated_adler, 0x0B290207, 0x6e0acdeb, 0x0b290207]
            for key in common_keys:
                if key not in self.keymap:
                    self.keymap[key] = self.DEFAULT_V4_KEY
                    self._d(f"Adicionada chave padrão {self.DEFAULT_V4_KEY} para compressed key 0x{key:08X}")

    def _d(self, *args):
        if self.debug:
            print("[kom_crypto debug]", *args)

    def clear(self):
        self.entries.clear()
        self.version = None
        self._raw_header = None
        self.encryption_key_index = None
        self.filetime = 0
        self.adler32_header = 0
        self.headersize = 0
        self.massfile_flavor = "KOG"

    def read_from_file(self, path: str):
        self.clear()
        with open(path, "rb") as f:
            # Ler magicword (52 bytes)
            magicword = f.read(52)
            if len(magicword) < 52:
                raise ValueError("Arquivo truncado (magicword)")
            
            parsed = _parse_version_and_flavor_from_magicblock(magicword)
            if parsed is None:
                f.seek(0)
                peek = f.read(256)
                idx = _find_massfile_magic_offset(peek)
                if idx != -1:
                    magicword = peek[idx:idx + 52]
                    parsed = _parse_version_and_flavor_from_magicblock(magicword)
                    if parsed is None:
                        raise ValueError("Magic inválido ou formato desconhecido")
                    f.seek(idx + 52)
                else:
                    raise ValueError("Magic inválido ou formato desconhecido")
            a, b, vernum, flavor = parsed
            self.version = vernum
            self.massfile_flavor = flavor
            self._d("Versão detectada:", vernum, f"(V.{a}.{b}.)", "flavor:", flavor)

            # Ler size e compressed (ambos uint32)
            raw = f.read(8)
            if len(raw) < 8:
                raise ValueError("Arquivo truncado após magic")
            size, compressed = struct.unpack("<2I", raw)
            self._d("size:", size, "compressed(key_index): 0x%08X" % compressed)
            self.encryption_key_index = compressed

            # DDTank Classic usa V1.0 (ver_num==10) ou V4
            if vernum == 4:
                self._read_v4(f, size, compressed, magicword)
            elif vernum == 10:
                self._read_v10(f, size, compressed, magicword, path)
            else:
                raise ValueError(f"Versão não suportada para DDTank Classic: {vernum} (esperado V4 ou V1.0)")

    def _read_v4(self, f, size: int, compressed: int, magicword: bytes):
        """Lê formato V4: header XML criptografado com Blowfish + blobs sequenciais"""
        # Ler filetime, adler32, headersize
        extra = f.read(12)
        if len(extra) < 12:
            raise ValueError("Cabeçalho v4 truncado")
        filetime, adler32, headersize = struct.unpack("<3I", extra)
        self.filetime = filetime
        self.adler32_header = adler32
        self.headersize = headersize
        self._d("filetime:", filetime, "adler32:", adler32, "headersize:", headersize)

        # Ler header
        header = f.read(headersize)
        if len(header) != headersize:
            raise ValueError("Não foi possível ler header completo")
        
        self._raw_header = header

        # Descriptografar header V4
        header_decrypted = False
        
        # Tentar descriptografar com keymap
        if compressed in self.keymap:
            seed = self.keymap[compressed]
            self._d(f"Descriptografando header V4 com seed {seed} (keymap)")
            try:
                header = _blowfish_decrypt_with_sha1_key(header, seed)
                header_decrypted = True
                self._d("Header V4 descriptografado com sucesso (keymap)")
            except Exception as e:
                self._d(f"Erro ao descriptografar com keymap: {e}")
        
        # Se não descriptografou e use_default_key está ativo, tentar chave padrão
        if not header_decrypted and self.use_default_key:
            # Tentar com a chave padrão diretamente (independente do compressed key)
            self._d(f"Tentando descriptografar com chave padrão {self.DEFAULT_V4_KEY}...")
            try:
                header_test = _blowfish_decrypt_with_sha1_key(header, self.DEFAULT_V4_KEY)
                # Verificar se descriptografou corretamente (deve conter XML)
                if b"<" in header_test[:500] or b"Files" in header_test[:500] or b"File" in header_test[:500]:
                    header = header_test
                    header_decrypted = True
                    self._d("Header V4 descriptografado com sucesso (chave padrão)")
                else:
                    self._d("Chave padrão não funcionou (header descriptografado não contém XML)")
            except Exception as e:
                self._d(f"Erro ao descriptografar com chave padrão: {e}")
        
        if not header_decrypted:
            raise ValueError(f"Não foi possível descriptografar header V4 (compressed key: 0x{compressed:08X})")

        # Parse XML do header
        entries_meta = self._parse_xml_header(header)
        
        # Ler blobs sequencialmente
        self._read_entries_from_stream(f, entries_meta)

    def _build_v10_entry_name(self, index: int, data: bytes, source_path: str) -> str:
        base = os.path.basename(source_path or "").lower()
        if base == "map.kom":
            return f"{index:02d}.stg"
        ext = _guess_entry_extension(data)
        return f"entry_{index:05d}{ext}"

    def _parse_v10_sequential_streams(self, payload: bytes, entries_count: int):
        """
        Fallback para KOG V1.0 quando o header binário não foi decodificado:
        assume blobs zlib sequenciais no payload.
        """
        streams = []
        rel_off = 0
        total = len(payload)
        for i in range(entries_count):
            if rel_off >= total:
                raise ValueError(f"Fim inesperado do payload no stream {i}/{entries_count}")
            chunk = payload[rel_off:]
            obj = zlib.decompressobj()
            try:
                data = obj.decompress(chunk)
                data += obj.flush()
            except Exception as e:
                raise ValueError(
                    f"KOG V1.0: falha ao descomprimir stream {i} no offset {rel_off}: {e}"
                ) from e
            used = len(chunk) - len(obj.unused_data)
            if used <= 0:
                raise ValueError(
                    f"KOG V1.0: stream {i} no offset {rel_off} consumiu 0 bytes"
                )
            comp = chunk[:used]
            streams.append((comp, data, rel_off))
            rel_off += used

        if rel_off != total:
            self._d(
                "Aviso: payload V1.0 tem bytes extras após streams:",
                total - rel_off,
            )
        return streams

    def _read_v10(self, f, entries_count: int, compressed: int, magicword: bytes, source_path: str):
        """
        Lê formato KOG V1.0 (DDTank Classic - Epic).
        Layout observado:
        - uint32 file_count (já recebido em entries_count)
        - uint32 compressed_flag
        - uint32 filetime
        - uint32 unk_v10
        - uint32 adler32_header
        - uint32 headersize
        - header binário (headersize bytes)
        - payload (blobs)
        """
        extra = f.read(16)
        if len(extra) < 16:
            raise ValueError("Cabecalho v1.0 truncado")
        filetime, unk_v10, adler32_header, headersize = struct.unpack("<4I", extra)
        self.filetime = filetime
        self.adler32_header = adler32_header
        self.headersize = headersize
        self._d(
            "v1.0 filetime:",
            filetime,
            "unk_v10:",
            unk_v10,
            "adler32:",
            adler32_header,
            "headersize:",
            headersize,
        )

        header = f.read(headersize)
        if len(header) != headersize:
            raise ValueError("Não foi possível ler header completo v1.0")
        self._raw_header = header
        calc = _adler32(header)
        if calc != adler32_header:
            self._d(
                f"Aviso: adler32 do header v1.0 não confere (esperado 0x{adler32_header:08X}, obtido 0x{calc:08X})"
            )

        # V1.0 moderno (Epic/Steam) usa header XML mascarado com XOR e payload
        # como blobs sequenciais de tamanho CompressedSize.
        entries_meta = None
        header_plain = header
        try:
            entries_meta = self._parse_xml_header(header_plain, base_offset=V10_HEADEROFFSET)
        except Exception as e_raw:
            # Tentar XOR conhecido (Epic client)
            try:
                header_plain = _xor_v10_header(header)
                self._d("Aplicado XOR do header v1.0 (V10_HEADER_XOR_KEY)")
                entries_meta = self._parse_xml_header(header_plain, base_offset=V10_HEADEROFFSET)
            except Exception as e_xor:
                self._d(
                    "KOG V1.0: falha ao parsear XML do header (raw/xor). "
                    "Usando fallback de streams zlib (pode falhar).",
                    e_raw,
                    e_xor,
                )

        if entries_meta is not None:
            if len(entries_meta) != entries_count:
                self._d(f"Aviso: XML retornou {len(entries_meta)} entradas, esperado {entries_count}")
            self._read_entries_from_stream(f, entries_meta)
            return

        # Fallback legado: tenta interpretar payload como streams zlib sequenciais.
        payload = f.read()
        streams = self._parse_v10_sequential_streams(payload, entries_count)
        for i, (comp_data, data, _) in enumerate(streams):
            name = self._build_v10_entry_name(i, data, source_path)
            self.entries.append({
                "name": name,
                "orig_size": len(data),
                "comp_size": len(comp_data),
                "data": data,
                "comp_data": comp_data,
                "checksum": "%08x" % (zlib.crc32(comp_data) & 0xFFFFFFFF),
                "filetime": filetime,
                "algorithm": 0,
            })

        self._d(f"Lidas {len(self.entries)} entradas (v1.0 fallback).")

    def _parse_xml_header(self, header_bytes: bytes, base_offset: int | None = None):
        """
        Parse XML header conforme ReadHeader do C++:
        Procura por tags <File> dentro de <Files>
        """
        self._d(f"Procurando XML no header ({len(header_bytes)} bytes)")
        
        # Procurar por padrões XML em bytes
        xml_start = None
        patterns = [
            b"<Files", b"<FileInfo", b"<?xml", b"<Files>", b"<FileInfo>",
            b"<files", b"<fileinfo", b"<File", b"<file"
        ]
        
        for pattern in patterns:
            idx = header_bytes.find(pattern)
            if idx != -1:
                xml_start = idx
                self._d(f"Encontrado padrão XML '{pattern.decode('latin-1', errors='ignore')}' na posição {idx}")
                break
        
        if xml_start is None:
            raise ValueError(f"Não foi possível encontrar início do XML no header ({len(header_bytes)} bytes)")
        
        # Extrair XML a partir da posição encontrada
        xml_bytes = header_bytes[xml_start:]
        
        # Tentar decodificar e parsear
        encodings = ["utf-8", "latin-1", "cp1252"]
        dom = None
        
        for enc in encodings:
            try:
                xml_text = xml_bytes.decode(enc, errors="ignore")
                # Limpar caracteres de controle que podem causar problemas
                xml_text = ''.join(c for c in xml_text if ord(c) >= 32 or c in '\n\r\t')
                dom = parseString(xml_text)
                self._d(f"XML parseado com sucesso usando encoding {enc}")
                break
            except Exception:
                continue
        
        if dom is None:
            raise ValueError("Não foi possível parsear XML do header")
        
        # Procurar por <Files> -> <File>
        files_node = None
        for node in dom.childNodes:
            if node.nodeType == node.ELEMENT_NODE:
                if node.nodeName == "Files":
                    files_node = node
                    break
                elif node.nodeName == "FileInfo":
                    # Procurar <Files> dentro de <FileInfo>
                    for child in node.childNodes:
                        if child.nodeType == child.ELEMENT_NODE and child.nodeName == "Files":
                            files_node = child
                            break
        
        if not files_node:
            raise ValueError("Tag <Files> não encontrada no XML")
        
        entries_meta = []
        boff = HEADEROFFSET if base_offset is None else int(base_offset)
        offset = boff + self.headersize  # offset inicial conforme C++
        
        # Iterar sobre <File> nodes
        for file_node in files_node.childNodes:
            if file_node.nodeType != file_node.ELEMENT_NODE:
                continue
            if file_node.nodeName != "File":
                continue
            
            # Ler atributos
            name = None
            size = 0
            compressedsize = 0
            checksum = 0
            filetime = 0
            algorithm = 0
             
            for attr_name, attr_value in file_node.attributes.items():
                if attr_name == "Name":
                    name = attr_value
                elif attr_name == "Size":
                    try:
                        size = int(attr_value)
                    except:
                        size = 0
                elif attr_name == "CompressedSize":
                    try:
                        compressedsize = int(attr_value)
                    except:
                        compressedsize = 0
                elif attr_name == "Checksum":
                    try:
                        checksum = int(attr_value, 16)  # hex
                    except:
                        checksum = 0
                elif attr_name == "FileTime":
                    try:
                        filetime = int(attr_value, 16)  # hex
                    except:
                        filetime = 0
                elif attr_name == "Algorithm":
                    try:
                        algorithm = int(attr_value)
                    except:
                        algorithm = 0
             
            if name:
                entries_meta.append({
                    'name': name,
                    'orig_size': size,
                    'comp_size': compressedsize,
                    'checksum': checksum,
                    'filetime': filetime,
                    'algorithm': algorithm,
                    'offset': offset
                })
                offset += compressedsize  # próximo offset
        
        self._d(f"Parseados {len(entries_meta)} arquivos do XML")
        return entries_meta

    def _read_entries_from_stream(self, f, entries_meta):
        """Lê blobs do arquivo conforme metadados"""
        self._d("Lendo blobs do arquivo...")
        
        for meta in entries_meta:
            name = meta['name']
            comp_size = meta['comp_size']
            orig_size = meta['orig_size']
            offset = meta.get('offset', f.tell())
            algorithm = meta.get('algorithm', 0)
            
            # Ir para offset se especificado
            if 'offset' in meta:
                f.seek(offset)
            
            comp_data = f.read(comp_size)
            if len(comp_data) != comp_size:
                raise ValueError(f"Dados truncados para {name}")
            
            # DDTank Classic usa apenas Algorithm 0 (zlib simples)
            if algorithm != 0:
                self._d(f"Aviso: arquivo {name} usa algorithm {algorithm} (não suportado, mantendo comprimido)")
                data = comp_data
            else:
                # Algorithm 0: zlib simples
                try:
                    if comp_size == orig_size:
                        data = comp_data
                    else:
                        data = zlib.decompress(comp_data)
                        if len(data) != orig_size:
                            self._d(f"Aviso: tamanho descomprimido não confere para {name}")
                except Exception as e:
                    self._d(f"Falha ao descomprimir {name}: {e}")
                    data = comp_data
             
            self.entries.append({
                'name': name,
                'orig_size': orig_size,
                'comp_size': comp_size,
                'data': data,
                'comp_data': comp_data,
                'checksum': "%08x" % meta.get('checksum', 0),
                'filetime': meta.get('filetime', 0),
                'algorithm': algorithm,
            })
        
        self._d(f"Lidos {len(self.entries)} entradas do arquivo.")
