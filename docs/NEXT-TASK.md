# Próxima tarefa — M1: ativação de um componente original legível

Estado em **2026-11-05**: M1.1 entrega inspeção de imports normais/atrasados, exports/forwarders, API Sets e recursos de ativação disponíveis, integrada ao JSON determinístico de `xboxone-systemos prepare`. A identidade e a revisão de cada provedor precisam ser verificadas; presença de export não autoriza sua execução. Oito grupos afetados passaram no Windows; CI dos três sistemas aguardando execução do commit M1.1. Evidência e limites em [M1-STATUS.md](M1-STATUS.md).

Os arquivos do OSU2 continuam expondo somente contêineres XVD, sem componente original diretamente legível. Nenhum boot, ativação original ou frame autêntico demonstrado. O próximo trabalho depende desse insumo; não repetir infraestrutura sintética aprovada nem pesquisas de criptografia já concluídas.

## Objetivo concreto

Identificar **um componente original do Xbox One já legível por acesso autorizado**, com módulos/recursos da própria revisão, preencher o manifesto implementado e estender o menor contrato realmente bloqueante até uma tentativa original verificável. O shell e a primeira imagem continuam dependentes desse insumo; não repetir a infraestrutura sintética já aprovada.

## Entradas e seleção

- Preservar os três ZIPs em Downloads. Os perfis da pré-checagem referenciam seus membros sem extração, duplicação ou mistura.
- O SystemOS de OSU2 e OSU3 é idêntico por SHA-256. Para a primeira análise histórica, uma única referência OSU2 evita trabalho duplicado sobre esse volume, mantendo OSU3 como pacote distinto pelo updater. Isso é prioridade de investigação, não uma versão de dashboard escolhida ou comprovadamente mais fácil.
- O OSU1 é uma alternativa posterior válida para investigação do One; `ScarlettHost.xvd` permanece fora do alvo One. Não transferir seus recursos ou versões para o conjunto histórico.
- Falta obter uma entrada original **já legível por um acesso autorizado**. Reconhecer cabeçalhos de OSU não supre isso. Não implementar bypass, extrair chaves ou afirmar que um flag de cabeçalho tornou o conteúdo acessível.

## Trabalho quando a entrada estiver disponível

1. Executar `inventory <raiz-do-conjunto> --json` e preencher o manifesto v1 de [M1-STATUS.md](M1-STATUS.md): revisão exata, identidade de fonte, origem declarada, caminho/hash/procedência por arquivo e bindings explicitamente auditados. Referenciar os originais no lugar, sem cópias; o manifesto não autentica a revisão declarada.
2. Identificar o shell e seu modelo de pacote/ativação a partir dos arquivos efetivamente encontrados, sem presumir nomes de executável ou a geração visual da dashboard.
3. Aplicar o grafo PE já implementado ao conjunto legível. Auditar o mapeamento exato de API Sets da revisão e interpretar seus metadados reais de pacote/WinRT/SxS. O parser preserva RT_MANIFEST/RT_VERSION e marca CLR/TLS; não resolve classes WinRT, schemas API Set, manifestos externos, serviços, assets ou comunicação com HostOS automaticamente.
4. Usar `xboxone-systemos prepare <manifesto>` para registrar dependências ausentes ou não implementadas. O backend atual aceita só EXE Win32 console com kernel32 auditado; imports privados/atrasados, WinRT, serviços, kernel NT e dispositivos exigem trabalho específico. Não escolher outro arquivo/OSU por basename.
5. Estender somente o contrato observado, com teste próprio. Quando kernel/dispositivo for indispensável, registrar símbolo/serviço/IOCTL e avaliar backend isolado. Só executar `run` após auditoria de ativação e dependências; saída 0 sozinha não prova inicialização original.

## Critérios de conclusão

- Um conjunto legível coerente por versão, com componente de shell identificado e hashes/procedência registrados.
- Grafo de dependências com falhas explícitas e nenhuma substituição silenciosa entre OSUs.
- Decisão justificada para a primeira tentativa de ativação, com testes focados sobre o contrato alterado.
- Atualizar `STATUS.md`, `docs/M1-STATUS.md` e este arquivo. Primeira imagem exige observar código e recursos originais renderizando, com identidade, logs e captura; rótulos de proveniência e contadores gráficos não bastam.

Se a entrada legível continuar ausente, manter o bloqueio identificado em vez de repetir hashes, reexecutar suítes aprovadas, gerar cópias de firmware ou simular progresso de boot.
