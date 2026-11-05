# CLAUDE.md — contexto persistente do xboxone-native

Antes de atuar, leia [AGENTS.md](AGENTS.md), [STATUS.md](STATUS.md) e [docs/M0.md](docs/M0.md). Estas instruções também se aplicam a Codex, Claude e outros agentes: o nome do arquivo não restringe seu alcance. O código atual da `main` e os testes reais prevalecem sobre expectativas antigas. Não inventar APIs, resultados, números de versão, compatibilidade, desempenho ou sucesso de inicialização.

## Missão permanente

Executar **o SystemOS original do Xbox One no PC**, preservando a dashboard verdadeira, Guide, biblioteca, perfis locais, seleção de jogo pela dashboard e retorno do GameOS ao SystemOS. O launcher desktop futuro é exclusivamente para instalação, importação, preparação e diagnóstico, **nunca** uma substituição visual da dashboard.

**Performance-first, correctness-preserving**: velocidade é prioridade com fidelidade e correção inegociáveis. Medir antes e depois (mesmo workload, hashes, plataforma, CPU/GPU, runtime, condições, repetições e métricas). Reportar inclusive resultados negativos. Não remover efeitos, impor limitações de CPU sem necessidade, introduzir retornos de sucesso falsos ou hacks por título no código compartilhado. Instrumentação opcional deve ficar desligada por padrão. Aceitação depende de testes de comportamento reais.

A execução x86-64 direta é preferida quando comprovada. A arquitetura deve suportar adaptadores de APIs/serviços e eventual VM/híbrido para partes do SystemOS que comprovadamente dependam disso. **Não presumir que o SystemOS é um processo Win32 comum.** Não portar a arquitetura PowerPC/AOT/ReXGlue do x360-native: somente práticas de projeto, UX, fidelidade, testes, desempenho, lançamento e controle de espaço são referências aproveitáveis.

## Estado real, não a visão futura

- `main` contém o **M0**, um inspetor C++20 somente leitura de cabeçalhos XVD e imagens PE32+ AMD64 com imports, CLI `inspect`, JSON e fixtures sintéticos.
- CMake compila a biblioteca `xboxone_inspection`, o executável `xboxone-native` e, se habilitados, os testes `inspection_regressions` e `cli_help`.
- A validação local inicial informou **2 testes CTest aprovados**; o workflow CI está configurado para Windows, Linux e macOS, sem atribuir suporte de runtime a esses sistemas.
- **Não há** shell original executado, primeira imagem, dashboard, Guide, importador, sistema de perfis, jogos, renderizadores Xbox/Native, GameOS funcional ou Release para usuário.
- O build SystemOS `10.0.10586.1029` aparece no material de pesquisa como **referência de inspeção**, não como primeiro alvo funcional escolhido. Não afirmar facilidade ou bootabilidade por esse número.

Atualize `STATUS.md` **somente** após mudança e evidência que alterem o estado. Para decisões e bloqueios específicos, mantenha `docs/M0.md` ou documento canônico de marco posterior; não abrir uma nova cópia de relatório a cada tentativa. READMEs EN/PT-BR devem permanecer consistentes.

## Arquitetura de referência e limites

```text
Desktop UI [futuro, apenas gestão]
  └── ContentInventory e versionamento (M0: somente inspeção)
       ├── SystemOS session [futuro]
       │    ├── backend de compatibilidade de componentes originais
       │    ├── backend de VM isolada, se exigido por dependências reais
       │    ├── app model/ativação, composição, controle, perfis e storage
       │    └── dashboard original e Guide
       └── GameOS session [futuro]
            ├── ERA x86-64 loader, KernelX e Xbox WinRT
            ├── D3D11.X, áudio, entrada, recursos e memória
            └── contratos de troca de sessão com SystemOS
```

**HostOS:** contratos necessários de dispositivo, virtualização e broker; não implementar hypervisor inteiro sem prova de necessidade. **SystemOS:** OneCoreUAP/shell e apps do sistema variam entre versões; a primeira imagem deve vir do original. **GameOS/ERA:** separação da sessão e dependências de jogos. **GameCore:** investigar separadamente, sem inferir equivalência.

Renderizadores futuros: `Xbox` (fidelidade do console, caminho de referência, sem efeitos faltantes) e `Native` (resolução/FPS/HDR e otimizações quando comprovadas sem degradar comportamento). D3D12/Vulkan/backends macOS precisam de contratos gráficos reais antes de serem declarados implementados. Não afirmar paridade com Azimuth/WinDurango sem medir em casos reproduzíveis.

## Fidelidade e isolamento de versão — permanentes

1. Cada perfil de SystemOS aponta **exclusivamente** para módulos, pacotes e recursos originais de **sua própria revisão**; o mesmo critério vale para GameOS/ERA, quando aplicável.
2. Registrar versão, proveniência verificável e SHA-256 por arquivo original permitido. Nomes de DLL, exports, ordinais ou classes WinRT iguais não demonstram compatibilidade entre versões.
3. Falta ou divergência de dependência = **erro legível**, nunca fallback silencioso para outra revisão, arquivo encontrado por basename ou cache global de módulos específicos.
4. Isolar arquivos originais de caches compartilhados. Não copiar componentes proprietários para o repositório, não reempacotar insumos sem autorização e não usar arquivos protegidos em fixtures/CI.
5. A primeira imagem da dashboard só conta com execução do **componente original**, dados corretos da mesma revisão, log, hash e captura verificável. Imagem ilustrativa, tela ImGui, screenshot e teste de janela sintética não contam.
6. Fidelidade de entrada, áudio, tempo, mensagens, serviços, perfis e armazenamento importa tanto quanto a imagem. Não declarar funcionalidade com base só em um frame.

## Provas de compatibilidade

| Estado | Evidência mínima |
|---|---|
| Identificado | Metadados reconhecidos, sem afirmar proveniência ou integridade adicional |
| Carregado | Imagem/módulo mapeado com validações relevantes |
| Inicializado | Entrada real no código original e runtime necessário respondendo corretamente |
| Renderizando | Frame produzido pelo componente real, com evidências e origem rastreáveis |
| Interface funcional | Entrada e navegação reais validadas no fluxo correspondente |
| Gameplay | Jogabilidade observada; não implica estabilidade ou progressão |
| Jogável | Progresso sustentado, entrada, áudio e persistência verificados no escopo definido |
| Totalmente funcional | Todos os fluxos relevantes de ponta a ponta comprovados |

`compilado`, `identificado`, `importado` e `inicializado` não são sinônimos. Os testes sintéticos M0 não comprovam boot, jogo ou dashboard.

## Arquivos e desempenho — sem duplicação

- Compartilhar **uma base C++20** para Windows, Linux e macOS; adapters isolam diferenças. ARM64 poderá exigir tradução de instruções, mas não impor um emulador/AOT x86-64 completo ao caminho x64 compatível.
- Suportar caminhos Unicode e longos, I/O centralizado e erros explícitos. Não exigir admin/Registro sem necessidade e autorização. Não criar cópias de todos os inputs para importar.
- Conteúdo original permanece no local do usuário, inalterado e identificável por hash. Cache futuro, quando inevitável, deve ser versionado, recuperável, auditável e deduplicado com regras de integridade; hardlinks somente quando seguros.
- Não ampliar `.local/`, `build/`, `evidence/` ou ZIPs com snapshots repetidos. Revisar bytes gerados antes/depois de mudanças em importação/preparação. Dados de usuário, perfis e saves não são descartáveis.
- Otimizações de CPU, imports, I/O, renderização e shaders só são aceitas com comparação reproduzível e testes de correção; não desativar efeitos nem inventar métricas.

## Uso dos projetos de referência e licenciamento

- [Xbox One Research](https://github.com/xboxoneresearch/wiki): fatos sobre HostOS, SystemOS, GameOS, dispositivos, XVD/XVC e inicialização; verificar o texto/revisão usada.
- [WinDurango](https://github.com/WinDurango/WinDurango): implementação ERA de KernelX, Xbox WinRT e D3D11.X no Windows; **LGPL-3.0**. Antes de incorporar código, decidir arquitetura e obrigações de redistribuição. Não presumir que ele executa a dashboard original.
- [Azimuth](https://almost-there-games.itch.io/azimuth): comportamento público e benchmark alvo; não presumir acesso ao código proprietário.
- [x360-native](https://github.com/fabegalo/x360-native): **referência de engenharia** (agentes, fidelidade, testes, seis targets, CI, caches, distribuição), não dependência de PowerPC/ReXGlue.
- Código original sob BSD-3-Clause. Não distribuir firmware, dashboards, XVD/XVC protegidos, jogos, chaves, dumps, recursos proprietários nem código derivado de binários sem autorização. Sem bypass de DRM ou extração de chaves.

## Processo obrigatório de alterações

1. Consultar a `main`, `STATUS.md` e o contrato existente; não começar reimplementando o que já existe.
2. Delimitar um único avanço com resultado observável e regressão focada; estudar o upstream pertinente antes de copiar/alterar implementação.
3. Implementar o mínimo correto, sem stubs com sucesso fictício e sem gerar cópias grandes ou documentação redundante.
4. Compilar **somente** os targets alterados, se houver mudanças de código. Usar testes sintéticos/focados. **Não rodar a suíte inteira por padrão**, nem sessões gráficas ou jogos sem necessidade e autorização.
5. Se o build falhar, não usar binário antigo para validar. Se faltar acesso ao sistema/arquivo original, registrar o bloqueio e validar apenas a parte sintética, sem afirmar boot.
6. Documentar comandos, ambiente, evidências e limitações com precisão; atualizar o arquivo canônico relevante e sincronizar ambos READMEs quando mudar o estado público.
7. Conventional Commit objetivo, sem créditos artificiais a agentes. Com autorização para o escopo e alteração da `main`, gravar nela sem PR; preservar branch/head e nunca usar force-push automático. **Não publicar Release sem autorização expressa.**

**Regras de interação dos agentes (herdadas da filosofia x360-native):** Computer Use requer autorização explícita; teste visual real e sessão longa de dashboard/jogos precisam de necessidade e autorização prévia; processos em segundo plano são supervisionados e limitados; se uma ferramenta exigir interação não autorizada, interromper esse passo e comunicar o bloqueio; não ampliar o escopo antes de concluir a tarefa atual.

## Comandos existentes — desenvolvimento, não certificação

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release -R "inspection_regressions|cli_help" --output-on-failure
./build/xboxone-native --help
./build/xboxone-native inspect /path/to/authorized/component.exe --json
```

Em Windows com gerador multiconfiguração, normalmente `build\\Release\\xboxone-native.exe`. Não executar o último comando sem arquivo autorizado. `cmake --build` e CTest não são evidências de execução de SystemOS. O workflow `.github/workflows/build.yml` possui runners Windows/Linux/macOS; nenhum resultado em ARM64 pode ser inferido do nome do host runner. Não criar patches de SDK, toolchains fixadas, comandos de bootstrap ou targets que ainda não existem.

## Próximo bloqueio técnico do M0

Ainda falta um **componente original do SystemOS, legível e legitimamente acessível**, com módulos e recursos compatíveis de mesma versão. O passo incremental planejado no [docs/M0.md](docs/M0.md) é inventário seguro somente leitura + hashes + grafo de dependências explícito e teste sintético de ativação (sem atribuir imagens à Microsoft). Não avançar para o marco de primeira imagem como se esse insumo já estivesse disponível.

Não transformar documentação de ambição em prova de funcionalidade. A versão vigente é a implementação inspecionada na `main`; este documento precisa acompanhar as evidências posteriores.
