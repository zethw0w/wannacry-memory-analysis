# Análise de Memória do WannaCry Ransomware

Extração de **Indicadores de Comprometimento (IoC)** do ransomware **WannaCry** a partir de um despejo de memória de um host Windows XP infectado, usando **Volatility 3**. Reproduz o roteiro da SANS de análise forense de memória (Defense Operations / FIAP).

> ⚠️ Nenhuma amostra de malware ativa é distribuída neste repositório — apenas as evidências (prints de comandos) extraídas em ambiente isolado (WSL).

## Metodologia

Partindo apenas do dump de memória (`Investigation-2.raw`, mesmo artefato do Caso 2 de Volatility), reconstruí a linha do tempo da infecção:

1. **`windows.info`** — Windows XP SP3, build `2600.xpsp_sp3_qfe.130704-0421`.
2. **`windows.pstree` / `psscan`** — identificada a cadeia de processos:
   `explorer → tasksche.exe (1940) → @WanaDecryptor@ (740)`, com `taskdl.exe`/`taskse.exe` já encerrados (visíveis só no `psscan`).
3. **`windows.dlllist --pid 740`** — o decryptor carrega `ws2_32.dll` (sockets), `wininet.dll` (rede), `advapi32.dll` (registro), `secur32.dll` (cripto), `urlmon.dll`.
4. **`windows.handles` / `mutantscan`** — mutex `MsWinZonesCacheCounterMutexA` (IoC conhecido).
5. **`windows.filescan | grep ivecuqmanpnirkt615`** — todos os artefatos `.wnry` no diretório de trabalho `C:\Intel\ivecuqmanpnirkt615\`.
6. **`windows.memmap --dump`** dos PIDs 1940 e 740 + `strings` — extração dos IoCs de rede.
7. **`windows.dumpfiles --pid 1940`** — extração do binário `tasksche.exe`, confirmado pelo SHA-256 `ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa` (hash público do WannaCry).

## IoCs extraídos

| Tipo | Indicador |
|---|---|
| Processos | `tasksche.exe`, `@WanaDecryptor@`, `taskse.exe`, `taskdl.exe` |
| Diretório de trabalho | `C:\Intel\ivecuqmanpnirkt615\` |
| Mutex | `MsWinZonesCacheCounterMutexA` |
| Comando de permissões | `icacls . /grant Everyone:F /T /C /Q` |
| Senha do arquivo ZIP interno | `WNcry@2ol7` |
| Kill-switch | `http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com` |
| Carteiras Bitcoin | `12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw`, `13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94`, `115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn` |
| Domínios .onion (C2 Tor) | `gx7ekbenv2riucmf`, `57g7spgrzlojinas`, `xxlvbrloxvriy2c5`, `76jdd2ir2embyv47`, `cwwnhwhlz52maqm7` `.onion` |
| SHA-256 do tasksche.exe | `ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa` |

## Estrutura

```
prints/ — info, pslist/psscan, dlllist, handles/mutex, filescan,
          memdumps, strings (onion/bitcoin/killswitch), análise estática do binário extraído
```
