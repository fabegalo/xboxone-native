# STATUS — xboxone-native

## 2026-11-04 — M1: sessão versionada e execução nativa sintética verificável

- **M0 publicado na `main`: `7307692`.** Preservados OSU1/2/3, perfis, hashes e originais. OSU2 é a referência histórica inicial de investigação; OSU3 compartilha seu SystemOS, mas continua pacote independente. Versão comercial da dashboard não confirmada; revisão bruta `0x341400004723ad20` não foi promovida a versão autenticada.
- Biblioteca independente `xboxone_systemos` e CLI `xboxone-systemos prepare|run`: manifesto por revisão, SHA-256/procedência por artefato, dependências explícitas sem fallback e diagnóstico de serviços ausentes. PE de kernel, DLL como entrada, CLR, imports atrasados/privados e contratos não auditados bloqueiam execução.
- Backend Windows AMD64 usa o loader real (`CreateProcessW`), confere exports kernel32 explicitamente autorizados e supervisiona um processo por Job Object, com prazo e limpeza após timeout. Memória, imports e threads foram exercitados por **código sintético próprio**, sem renderer ou código Xbox.
- **Build Release Windows x64/MSVC 19.44.35229 aprovado; sete grupos focados passaram**, incluindo inspeção/inventário, ZIP/pré-checagem e os três grupos de bootstrap. Na última revisão do bootstrap: **103 verificações estruturais, 19 nativas e 7 testes Python de CLI**, incluindo falha do loader, saída 27, timeout sem filho vivo, Unicode, hashes e versões divergentes. Symlinks/junction foram pulados por falta de privilégio. Linux/macOS/ARM64 não executados.
- Evidência local: `build-m1/m1-bootstrap-evidence.json` registra PID real, retomada da thread, `stage=exited`, `exit_code=0`, origem sintética e **zero frames autênticos**. O componente verificou memória/proteção e uma thread real. Nenhum executável original SystemOS estava legível; não houve tentativa de executar conteúdo criptografado ou alegação de dashboard inicializada.
- Contrato de entrega ao backend gráfico paralelo, limitações e dependências: [docs/M1-STATUS.md](docs/M1-STATUS.md). Código gráfico concorrente preservado. Próxima etapa: [docs/NEXT-TASK.md](docs/NEXT-TASK.md). Nenhuma Release publicada.

## 2026-11-04 — M0 retomado: OSUs separados por alvo e pré-checagem SystemOS

- **Manter OSU1, OSU2 e OSU3.** OSU1 contém candidatos Xbox One e componentes Scarlett; OSU2/OSU3 são bases históricas do Xbox One original. Nenhum ZIP fornecido foi identificado como exclusivamente de outro console. `ScarlettHost.xvd` foi excluído da seleção SystemOS/One, sem apagar ou reempacotar o OSU1. A classificação usa o papel OSU registrado e o layout observado, não autenticação Microsoft.
- `tools/systemos_preflight.py` implementado: verifica novamente o SHA-256 do ZIP, compara prefixos nativos e metadados com o estudo completo anterior e cria um perfil isolado por arquivo. Não usa o nome atual do ZIP como identidade nem busca componentes em outro pacote. Hashes completos dos membros são reutilizados do estudo anterior, vinculados ao hash verificado do ZIP; não foram recalculados nesta rodada.
- Aplicação real aos três insumos: 37 candidatos SystemOS/recursos no OSU1 e 2 em cada OSU legado, sem divergência de revisão nos conjuntos selecionados. HostOS/templates permanecem como referências; ERA, firmware, atualizador, utilitários de desenvolvimento e Scarlett não são tratados como executáveis do shell. `uERA.xvd` tem revisão própria e não foi misturado ao SystemOS.
- Os 62 XVDs continuam com o bit de desativação de criptografia ausente. Nenhum PE interno foi obtido. As atualizações também não contêm volumes inicializados `settings-saved.xvd`/`user.xvd`; isso é ausência de estado de console, não prova de defeito no OSU. Não foram criados volumes vazios.
- **9 testes novos de pré-checagem passaram** no Windows x64, com fixtures sintéticas: identidade por hash, renomeação, alteração de ZIP, adulteração de referência, catálogo inválido, revisão misturada, flag sem criptografia e exclusão de Scarlett/ERA. Pacote desconhecido recebe classificação indeterminada, não uma afirmação de ausência de conteúdo One. O novo teste está registrado no CTest; as suítes anteriores não foram repetidas. Não houve alteração C++ nesta retomada nem execução de componentes originais.
- Detalhes, classificação para limpeza e comandos: [docs/M0-STATUS.md](docs/M0-STATUS.md). Próximo trabalho: [docs/NEXT-TASK.md](docs/NEXT-TASK.md). READMEs, AGENTS, CLAUDE e documentos de pesquisa existentes permaneceram inalterados nesta retomada.

## 2026-11-04 — incremento local de inventário e estudo dos insumos

- `inventory <directory> --json` implementado com SHA-256 por streaming, caminhos relativos determinísticos, limites e exclusão de symlinks/reparse points. Imports agrupados com estados `not_in_inventory`, `present_unverified` e `ambiguous`; presença não certifica versão, exports ou ABI.
- `inspect-xvd-header` e `tools/study_update_zip.py` estudam prefixos em memória sem extração, reutilizando o parser C++. Metadados brutos de flags, versão de pacote e FILETIME foram adicionados. A assinatura real minúscula `msft-xvd` e a compilação dos argumentos Unicode no Windows foram corrigidas.
- Insumos locais: Azimuth (23 arquivos, 11 PE AMD64), OSU1 (46 XVDs), OSU2 e OSU3 (8 cada). Hashes completos e CRC dos membros OSU verificados por streaming; assinatura Microsoft e árvore de integridade XVD não verificadas. Sete membros de OSU2/3 são idênticos por SHA-256; `updater.xvd` difere. [Estudo e manifestos](docs/research/input-study.md).
- Validação local Windows x64/MSVC 19.44 Release: os quatro grupos CTest passaram com fixtures sintéticas. Criação de symlinks e junctions foi recusada pelo ambiente local; esses casos estão implementados, mas foram pulados neste host. Linux/macOS não foram executados nesta sessão. Não há benchmark ou compatibilidade de runtime demonstrados.
- Arquivos originais preservados em Downloads; nenhuma extração, execução de membros, cópia de firmware ou dependência proprietária adicionada. Alterações de implementação permanecem locais até commit/revisão.

## 2026-11-04 — M0 publicado na `main`

- Repositório existente iniciado com CLI, biblioteca e testes C++20/CMake. Primeiro commit de documentação: `0edf8ca`; incremento funcional M0: `4ad22ab`.
- `inspect <file> [--json]` lê **sem copiar ou modificar** cabeçalhos XVD (metadados, sem validar assinatura ou descriptografar) e PE32+ AMD64 (características, DLLs e símbolos importados).
- Validação local inicial: build Linux concluído e **2 testes CTest aprovados** com fixtures sintéticas. O workflow GitHub Actions está configurado para Windows, Linux e macOS; a execução dos runners e todos os targets ARM64 **não estão certificados** por este registro.
- **Nenhum componente original do SystemOS foi executado.** Não existem primeira imagem, boot da dashboard, Guide, launcher gráfico, backend de GameOS, jogo executado, renderizador ou Release para usuários.
- Arquitetura provisória: inspeção e inventário compartilhados, fronteiras separadas de SystemOS e GameOS, execução x86-64 direta apenas onde viável e VM/híbrido quando necessário. Ver [docs/M0.md](docs/M0.md).

## Bloqueio atual

Para alcançar a primeira imagem autêntica, são necessários um componente original do SystemOS **legalmente legível** e seus recursos da mesma versão, mais um mapa de dependências (PE/WinRT/NT, pacote, composição, broker e dispositivos). O XVD reconhecido pelo inspetor não fornece esses componentes automaticamente.

**Próximo incremento:** [docs/NEXT-TASK.md](docs/NEXT-TASK.md). O diagnóstico por pacote e as referências SystemOS já existem. Falta um conjunto original legível para identificar o shell, fixar seu manifesto por versão e mapear PE/WinRT/NT, recursos e dispositivos. A pré-checagem retorna bloqueio explícito; não simula a dashboard.

**Regra de leitura:** status acima é evidência de ferramentas de inspeção, não compatibilidade de software Xbox One. Toda nova afirmação de boot, imagem ou jogabilidade precisa de teste real e versão/hash identificados.
