# M1 — bootstrap SystemOS e execução nativa limitada

Data: **2026-11-04**. Estágio máximo demonstrado: um **componente sintético próprio** foi criado como processo Windows AMD64, executou código de memória/threads/imports e terminou com código 0. **Nenhum componente original do SystemOS foi carregado ou inicializado; zero frames autênticos.**

## M0 publicado e candidato inicial

O commit `7307692` publicou na `main` o inventário, os adaptadores ZIP, a pré-checagem, os perfis por identidade e os metadados de OSU1/2/3. Nenhum ZIP/membro original foi alterado, extraído ou duplicado. As evidências anteriores estão em [M0-STATUS.md](M0-STATUS.md); hashes completos dos arquivos não foram recalculados desnecessariamente no M1.

**OSU2 é a referência inicial de investigação**, identificado pelo SHA-256 `74ca6bb17197689e9861a105021a8aaaf827b7a3b4b13e35a5562de32a04b326`. OSU3 mantém identidade própria `07092f55b25ff8615da866bfcbf7d162c9ed4f9810b1eb80ce336f9e560cac07`: compartilha sete membros com OSU2, mas seu updater difere. Não são perfis intercambiáveis.

O `system.xvd` de ambos tem SHA-256 `52d048663a33d30b2a46a6817b496c7d878e8bb4f3af36a1a15c20acb0bd3dcc`, criação declarada em 2015-09-04 e campo opaco de revisão `0x341400004723ad20`. Nesta sessão foram relidos apenas os prefixos de `system.xvd` de OSU2/3, em memória, e seus hashes de prefixo coincidiram com o catálogo. **Não há versão comercial da dashboard autenticada**, manifesto interno legível ou alvo de boot validado. Não converter esse inteiro opaco em `10.0.10586.1029` ou outra versão presumida. O mapeamento público de [campos XVD](https://github.com/emoose/xvdtool/blob/master/LibXboxOne/XVD/XVDStructs.cs) é referência de formato, não autenticação nem prova de semântica para todos os layouts históricos; nenhum código desse projeto foi incorporado.

Os volumes observados são `system.xvd` e `systemaux.xvd`; `host.xvd` e templates permanecem referências do mesmo pacote. Segundo a [pesquisa de SystemOS e volumes](https://xboxoneresearch.github.io/wiki/operating-system/xbox-operating-system/), o sistema também usa estado persistente separado. Os OSUs não fornecem `settings-saved.xvd`/`user.xvd` inicializados. O bit `EncryptionDisabled` permanece ausente nos XVDs examinados. Não há executável original legível para tentar ativação: o máximo original continua sendo identificação de contêiner, sem montagem ou execução.

## Implementação entregue

- `xboxone_systemos`: biblioteca C++20 independente, reutiliza `xboxone_inspection` e seu SHA-256 por streaming. `inventory::fingerprint` expõe a política existente para arquivos individuais e recursos, sem copiar entradas.
- `Session::prepare`: fixa identidade/revisão/procedência por artefato, confere hashes, rejeita caminhos relativos/links/reparse points, duplicidades e versões divergentes; inspeciona o PE e resolve cada import contra um binding explícito do perfil. Limites: 256 artefatos, 256 MiB por arquivo, 1 GiB por conjunto, 4096 bindings e 256 serviços.
- A única associação nativa atual é **`kernel32.dll` → `host:kernel32`**, solicitada explicitamente e com evidência de compatibilidade. Cada símbolo nomeado é conferido com `GetProcAddress` no módulo já carregado do Windows. Ordinais são recusados. A presença de uma DLL de mesmo nome nunca cria associação automática.
- Dependências privadas usam IDs exatos `artifact:<id>`. A identidade pode ser localizada, mas exports/forwarders e busca isolada de DLLs ainda não são resolvidos: **bloqueiam execução**. Imports sem binding, provedores desconhecidos e bindings ambíguos/inúteis geram erros.
- Mapa de serviços com evidência declarada: kernel NT/dispositivo Xbox exige avaliação de backend isolado; broker Xbox, ativação WinRT, compositor e storage exigem adaptadores ausentes. Nenhum serviço retorna sucesso substituto.
- `Session::run`: revalida o conjunto, mantém o EXE aberto sem compartilhamento de escrita/exclusão, recalcula sua identidade sob esse handle e usa `CreateProcessW` com caminho absoluto, suspenso, sem shell, handles herdados ou janela de console. Associa um Job Object antes de retomar a thread principal, limita a um processo, supervisiona prazo de 1..60000 ms e observa término após timeout. Não é uma sandbox de segurança ou uma VM.
- Estados distintos: `empty`, `blocked`, `prepared`, `process_created`, `running`, `exited`, `timed_out`, `failed`. PID, retomada da thread, código de saída e diagnósticos ficam no relatório. `exited` significa apenas término observado com código 0; não certifica entrada principal, inicialização do app ou dashboard de um binário arbitrário.
- `xboxone-systemos prepare|run`: CLI separada, JSON, código 0 para preparação/execução concluída, 1 para bloqueio/falha e 2 para uso/manifesto inválido.

A ativação implementada aceita somente **EXE Win32 console PE32+ AMD64 auditado em Windows AMD64 nativo**. DLL como entrada, subsistema nativo/driver, import atrasado e CLR são recusados explicitamente. Não há suporte de runtime demonstrado para Linux/macOS/ARM64; a mesma base C++ compila os diagnósticos e mantém a fronteira do adaptador Windows.

O loader do Windows cuida de mapeamento, relocação, imports, memória de imagem, TLS/unwind e thread inicial; não foi escrito um segundo loader PE. A delegação não significa que todos esses mecanismos tenham sido exercitados pela fixture. Referências de contrato: [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw), [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects), [PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) e [busca de DLLs](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order). Forwarders e dependências do Windows pertencem ao host, nunca a outro perfil Xbox.

## Manifesto v1

Texto UTF-8 de até 1 MiB, até 8192 linhas e 8192 bytes por linha. Comentários ocupam linhas iniciadas por `#`. Strings seguem `std::quoted`: aspas e barras invertidas são escapadas com `\`; prefira `/` nos caminhos. Registros desconhecidos, repetição de `profile`/`entry` e tokens extras são erros.

```text
xboxone-systemos-v1
profile "id" "revisao-exata" synthetic "sha256-da-fonte"
entry "componente"
artifact "componente" "revisao-exata" "C:/caminho/existente.exe" "sha256-do-arquivo" executable "procedencia e acesso autorizado"
bind "componente" "kernel32.dll" "host:kernel32" "evidencia de compatibilidade das APIs utilizadas"
```

O exemplo descreve a gramática, não um perfil pronto. Hashes devem ser 64 dígitos hexadecimais minúsculos. `original`/`synthetic` são declarações de origem, não autenticação Microsoft. Cada artefato exige sua procedência e revisão exata. Papéis: `executable`, `module`, `resource`, `container`. Recursos são identificados por hash, sem afirmar que seu formato foi decodificado. Requisitos opcionais: `service "id" <nt_kernel|xbox_device|xbox_broker|winrt_activation|compositor|storage> "evidencia"`. Sua presença atualmente bloqueia a execução com a categoria correspondente.

O arquivo de manifesto não prova por si só que a revisão declarada é verdadeira nem que todas as dependências dinâmicas foram auditadas. A entrada exige investigação real dos contratos do componente. Carregamentos dinâmicos, SxS, pacote/WinRT, serviços e acesso a recursos não são virtualizados/interceptados. As verificações de caminho pressupõem ancestrais estáveis; não fornecem snapshot atômico de um filesystem hostil. Nenhuma dessas limitações é convertida em compatibilidade declarada.

## Evidência e regressões focadas

Windows AMD64, MSVC **19.44.35229**, Windows SDK 10.0.26100, CMake 3.31.6/Ninja, configuração Release. A primeira configuração foi interrompida na sondagem de ABI; a seguinte teve erro LNK1104 no link incremental da sondagem. A configuração limpa com `CMAKE_TRY_COMPILE_CONFIGURATION=Release`, política CMP0141 NEW, `/Z7` e debug information Embedded concluiu. Nenhum binário antigo foi usado após falha.

Em ambiente MSVC x64, com CMake acessível:

```powershell
cmake -S . -B build-m1 -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_TRY_COMPILE_CONFIGURATION=Release -DCMAKE_POLICY_DEFAULT_CMP0141=NEW -DCMAKE_MSVC_DEBUG_INFORMATION_FORMAT=Embedded -DCMAKE_CXX_FLAGS=/EHsc -DCMAKE_CXX_FLAGS_DEBUG=/Z7 -DCMAKE_DEPENDS_USE_COMPILER=FALSE -DPython3_EXECUTABLE=<python-local>
cmake --build build-m1 --target xboxone-systemos xboxone_bootstrap_tests bootstrap_component_ok bootstrap_component_hang bootstrap_component_fail xboxone_inspection_tests xboxone_inventory_tests
ctest --test-dir build-m1 -R '^(bootstrap_regressions|bootstrap_native_execution|bootstrap_cli_regressions|inspection_regressions|inventory_regressions)$' --output-on-failure -V
```

Os cinco grupos passaram. Após ampliar os casos de erro e corrigir o escape JSON/limites do manifesto, somente os três grupos `bootstrap_*` foram repetidos: **103 verificações estruturais, 19 de execução nativa e 7 testes Python de CLI aprovados**. Inspeção/inventário permaneceram aprovados. O inspetor também foi recompilado e passaram `update_zip_and_cli_regressions` e `systemos_preflight_regressions` (9 casos), cobrindo os consumidores do parser alterado: **sete grupos focados aprovados ao todo**, sem suíte gráfica/ajuda. Symlinks de diretório/arquivo e junction foram pulados por falta de privilégio no host. Não houve teste visual, sessão gráfica ou jogo nesta tarefa.

`bootstrap_component_ok.exe` é produzido de `tests/bootstrap_component.cpp`, sem CRT e somente com imports kernel32. Seu código aloca 4096 bytes, cria uma thread que escreve 1024 palavras, aguarda/valida resultado e dados, muda a proteção para leitura e libera memória/handle. Só termina com 0 após todas essas operações reais. As outras variantes terminam com 27 ou aguardam indefinidamente; a sessão registra a falha e mata/aguarda a variante com timeout de 100 ms. O teste verifica que não ficou filho vivo. O PE estrutural inválido também prova que inspeção aprovada não equivale a aceitação pelo loader.

Evidência local única, em saída ignorada: `build-m1/m1-bootstrap-evidence.json` e seu `.manifest`, produzidos pelo teste de CLI. Executável sintético desta compilação: SHA-256 `d2bca9b483f5337541bbe7838e5574b7f379dec43d1f90b7452941b0f130330d`. O JSON registra `declared_origin=synthetic`, PID real, `primary_thread_resumed=true`, `stage=exited`, `exit_code=0`, `dashboard_boot_verified=false` e `authentic_frames_observed=0`. PID e hash podem mudar em nova compilação/execução; o teste confere o arquivo efetivamente executado.

## Contrato com a apresentação paralela

O bootstrap não depende do renderer e não modifica `presentation.h`, seus backends ou testes. A ponte futura reutiliza as interfaces já presentes no trabalho paralelo, sem outro renderer:

1. O produtor precisa ser um componente **original observado em execução**, com executável/recursos identificados e revisão validada. Um rótulo `original` no manifesto, `exited` ou contador de frames não satisfaz essa prova.
2. Para staging CPU, usar `presentation::ExternalFrameView`: RGBA8/BGRA8, dimensões, `row_pitch_bytes` e span válido até `Presenter::present_frame` terminar sua leitura. A ponte entre processo produtor e host ainda precisa de transporte/ownership; nenhum ponteiro do processo filho é válido diretamente no host.
3. `FrameProvenance` deve carregar `FrameOrigin::systemos_component`, ID do componente, hash conferido e `system_version_raw` não nulo da revisão realmente identificada. A revisão textual/opaqua do bootstrap **não** deve ser convertida em versão numérica inventada. Origem sintética continua `synthetic_test`.
4. `SystemOsSurfaceHandoffDesc` descreve a intenção de handles GPU. Vida útil, ownership, estado da textura e sincronização por fence entre produtor/consumidor ainda precisam de contrato e implementação antes de aceitar esse caminho. Um descritor validado não prova consumo/apresentação de textura compartilhada.
5. Primeira imagem exige log de ativação original, identidade de código/recursos, frame realmente entregue ao backend e captura observada/autorizada. Esta tarefa não emite frames nem incrementa contadores gráficos.

## Dependências ainda bloqueantes

| Dependência | Evidência atual | Próximo componente viável |
|---|---|---|
| PE/manifesto original legível e assets | OSUs examinados só expõem XVDs com criptografia indicada | Entrada já legível obtida por acesso autorizado; inventário/manifesto, sem extração de chaves |
| Versão comercial e modelo de ativação | Apenas identidade de pacote/campo bruto; nenhum shell interno legível | Verificar recursos de versão, pacote e metadados do conjunto original |
| Imports privados/atrasados, exports, forwarders/API sets | Bloqueados explicitamente; fixture só kernel32 | Ampliar o resolvedor a partir de dependência concreta observada, com fixture própria |
| Broker, WinRT, compositor e storage | Categorias de requisito implementadas; nenhum contrato original examinado | Auditar serviço/ABI real e implementar o menor adaptador fiel |
| Kernel NT/dispositivo Xbox/HostOS | Não foi encontrada dependência de um executável original legível | Quando observada, registrar símbolo/IOCTL/serviço exato e avaliar backend isolado, sem hypervisor especulativo |
| Transporte de frames do componente original | Apresentação paralela é infraestrutura separada | Definir transporte e sincronização após conhecer a superfície realmente produzida |

Não há evidência suficiente para escolher uma VM concreta ou afirmar que o shell será Win32 console. M1 comprova infraestrutura de inicialização executável e testável no Windows x64; bootstrap completo de SystemOS e primeira imagem continuam pendentes.
