# Próxima tarefa — M0: componente SystemOS legível

Estado em **2026-11-04**: os três OSUs foram identificados por hash e separados por alvo em [M0-STATUS.md](M0-STATUS.md). Nenhum é descartável inteiro por ser exclusivamente de outro console. A dashboard original permanece sem execução; a pré-checagem informa os bloqueios reais.

## Objetivo concreto

Identificar **um componente de shell original do Xbox One, legível e legitimamente acessível**, com os módulos e recursos da própria revisão, e produzir seu manifesto de identidade e grafo de dependências. Não substituir a dashboard por uma interface do projeto.

## Entradas e seleção

- Preservar os três ZIPs em Downloads. Os perfis da pré-checagem referenciam seus membros sem extração, duplicação ou mistura.
- O SystemOS de OSU2 e OSU3 é idêntico por SHA-256. Para a primeira análise histórica, uma única referência OSU2 evita trabalho duplicado sobre esse volume, mantendo OSU3 como pacote distinto pelo updater. Isso é prioridade de investigação, não uma versão de dashboard escolhida ou comprovadamente mais fácil.
- O OSU1 é uma alternativa posterior válida para investigação do One; `ScarlettHost.xvd` permanece fora do alvo One. Não transferir seus recursos ou versões para o conjunto histórico.
- Falta obter uma entrada original **já legível por um acesso autorizado**. Reconhecer cabeçalhos de OSU não supre isso. Não implementar bypass, extrair chaves ou afirmar que um flag de cabeçalho tornou o conteúdo acessível.

## Trabalho quando a entrada estiver disponível

1. Executar `inventory <raiz-do-conjunto> --json`, ajustando limites de leitura explicitamente quando necessário. Registrar procedência, revisão, caminhos e SHA-256 em um manifesto que referencie os arquivos existentes.
2. Identificar o shell e seu modelo de pacote/ativação a partir dos arquivos efetivamente encontrados, sem presumir nomes de executável ou a geração visual da dashboard.
3. Mapear imports normais e atrasados, exports/forwarders, contratos de API, classes WinRT, serviços NT, assets, recursos de idioma, composição e comunicação com HostOS. O parser atual de imports não certifica esses contratos completos.
4. Classificar dependências com evidência: presente e identificado, ausente, contrato por implementar ou necessidade de isolamento a investigar. Não resolver por basename em outros OSUs, fornecer sucesso fictício ou carregar código antes da auditoria do conjunto.
5. Escolher o menor caminho de ativação que preserve o comportamento original. Implementar e testar o contrato concreto identificado com fixtures próprias; não construir um loader/VM genérico baseado em dependências ainda desconhecidas.

## Critérios de conclusão

- Um conjunto legível coerente por versão, com componente de shell identificado e hashes/procedência registrados.
- Grafo de dependências com falhas explícitas e nenhuma substituição silenciosa entre OSUs.
- Decisão justificada para a primeira tentativa de ativação, com testes focados sobre o contrato alterado.
- Atualização somente de `STATUS.md`, `docs/M0-STATUS.md` e deste arquivo. Primeira imagem só será registrada após observar código e recursos originais renderizando, com evidência real.

Se a entrada legível continuar ausente, manter o bloqueio identificado em vez de repetir hashes, reexecutar suítes aprovadas, gerar cópias de firmware ou simular progresso de boot.
