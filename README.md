# Vanguard Emulator (Ofuscado)

Um emulador leve do serviço **vgc** (Riot Vanguard), reescrito e modernizado com foco em segurança, portabilidade e bypass dinâmico. Ideal para depuração de rede e isolamento de dependências ao analisar as comunicações do client-side do jogo VALORANT.

> **Autor:** realsoninho
> **Linguagem:** C++17
> **Plataforma:** Windows x64

---

## 🛠️ Principais Recursos Implementados

O desenvolvimento do emulador foca em **Métodos Únicos** de evasão e anonimização:

1. **Geração Dinâmica de UUID (Cabeçalho de Gateway)**: O projeto abandonou a utilização de identificadores (HWID/UUID) estáticos. A cada inicialização, um novo `X-VG-2` dinâmico e anônimo é gerado nativamente com as bibliotecas do Windows, mitigando bloqueios em massa ou rastreamento em cadeia pela rede.
2. **Obfuscação XOR Integrada**: Proteção agressiva do binário compilado. Strings críticas em texto legível como `eu.vg.ac.pvp.net` (Gateway) e outras chamadas ao Anti-Cheat não aparecem no Hexdump. O motor embutido `xorstr.hpp` cifra tudo e só os desencapsula diretamente na memória no momento da alocação de uso.
3. **Polimorfismo (Junk Code)**: O sistema conta com diretivas macros que usam o contador do compilador (`__COUNTER__`) misturado ao relógio da compilação (`__TIME__`). Isso força com que cada clique em "Build" resulte em um **SHA-256 e uma Assinatura Binária inteiramente inédita**, anulando a eficácia da detecção baseada em _signature-scan_.
4. **Resolução Dinâmica do VAN-72 e Rate Limit**: Patches diretos contra problemas de _pipeline_ quebrados do Vanguard, com checagem de timeout nos pacotes HTTP e delays para impedir retornos de "Rate Limited" pelo servidor Riot.

---

## 🚀 Como Compilar e Usar

### Pré-requisitos
- **Visual Studio 2019 / 2022** com carga de trabalho "Desenvolvimento para Desktop com C++".
- SDK do Windows 10/11 atualizado.

### Passos de Instalação e Execução

1. **Preparação dos Arquivos de Autenticação**
   Antes de rodar, garanta que os arquivos de interceptação da sessão original estejam na mesma pasta do seu emulador `.exe`:
   - `auth.bin` (contém o seu token do riot client cifrado ou injetado).
   - `request_content.x-protobuf` (sua sessão do game/vanguard interceptada).

2. **Compilando o Emulador**
   - Abra a Solução `vgc_emu.sln` no Visual Studio.
   - Selecione a Configuração de Build: **`Release`** e Plataforma **`x64`**.
   - Compile a solução (<kbd>Ctrl</kbd> + <kbd>Shift</kbd> + <kbd>B</kbd>).

3. **Iniciando a Simulação (Pipe Injection)**
   - O emulador deve ser **executado como Administrador**. Ele precisará derrubar o serviço original (`vgc.exe`/`vgk.sys`) para assumir a porta de escuta (`PIPE_NAME`).
   - Você verá o status de `Waiting for Valorant...`
   - Abra o VALORANT. O jogo enviará o heartbeat ao invés de pro Driver Original, para o seu executável local. 
   - Acompanhe no Terminal (console) as mensagens PT-BR do fluxo das requisições e a injeção do UUID único na sessão do jogo.

---

## 📂 Ferramentas Complementares no Repositório

O projeto também acompanha ferramentas nativas em **PowerShell** para facilitar o troubleshooting das requisições:

- `analyze.ps1`: Escaneia os cabeçalhos Vanguard presentes nas streams de bytes (`.bin`) na pasta atual e valida se a Assinatura ("realsoninho") está configurada corretamente no seu pacote.
- `hexdump.ps1`: Renderiza as strings brutas em hexadecimal para varredura de plaintexts (útil para analisar a integridade do seu payload cifrado).
- `proto_decode.ps1`: Um decodificador de buffer _varint_ embutido do Protobuf para ler e interpretar as streams locais `request_content.x-protobuf`.

---

> **Aviso Legal:**
> Este projeto foi desenvolvido para fins **educacionais, depuração e pesquisa de segurança da informação** a respeito da estrutura Client-Server do Vanguard. O autor não encoraja ou endossa o uso desta ferramenta com o intuito de violar Termos de Serviço em ambientes competitivos online.

*Feito com 💜 e dedicação de segurança cibernética por realsoninho.*
