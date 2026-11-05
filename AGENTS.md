# Trabalho dos agentes — xboxone-native

Leia **`CLAUDE.md`**, **`STATUS.md`** e **`docs/M0.md`** antes de alterar o projeto. Estas regras valem para Claude, Codex e qualquer agente de desenvolvimento. Use a `main` real como fonte de verdade; não invente recursos, resultados de build, APIs, arquivos ou compatibilidade.

## Performance-first, correctness-preserving — regra permanente

Desempenho é objetivo central, sem sacrificar correção, compatibilidade, fidelidade visual, temporização, armazenamento e semântica do Xbox One. Toda otimização exige medição antes/depois em cenários equivalentes e regressão focada; registrar resultados sem ganho. Evitar overhead desnecessário no caminho principal. Instrumentação deve ser opcional e desligada normalmente. Correções gerais devem servir a diversos componentes/jogos, não depender de hacks por título.

## Fidelidade ao SystemOS original — regra permanente

A **dashboard original** é o produto-alvo; o launcher futuro serve somente a importação, diagnóstico, preparação e início. Não criar dashboard falsa, Guide simulado, screenshot como saída do runtime ou interface que substitua a original. A primeira imagem válida precisa ser renderizada por **código e recursos originais autorizados**, com versão, hash, logs e captura de execução real. Nunca confundir inspeção, compilação, carregamento, inicialização, renderização, interação, gameplay e estado jogável.

HostOS, SystemOS, GameOS/ERA e GameCore não são equivalentes. x86-64 no PC não dispensa APIs, serviços, isolamento ou dispositivos do Xbox. Preferir execução direta onde comprovadamente viável; adotar VM ou híbrido somente com dependência técnica identificada. Não transplantar arquitetura PowerPC, AOT/ReXGlue ou XAM do x360-native.

## Isolamento de versões — regra arquitetural permanente

**Cada versão do SystemOS usa somente seus módulos, pacotes, recursos e dependências originais correspondentes.** Identificar a proveniência e SHA-256 de cada artefato autorizado. Rejeitar versões misturadas, dependências ausentes e ambiguidades com erro explícito; nunca aplicar fallback silencioso por nome, DLL/WinRT class, API ou versão. Infraestrutura genérica pode ser compartilhada, mas **não** módulos proprietários específicos. O build `10.0.10586.1029` é referência de pesquisa, não alvo escolhido ou validado.

## Dados, espaço e licenças — regras permanentes

- **Uma base C++ compartilhada** para Windows, Linux e macOS. Usar adaptadores de plataforma, sem forks com cópias do projeto.
- Não duplicar jogos, firmware, importações ou caches desnecessariamente. Inspeção M0 é somente leitura; preservar arquivos do usuário, usar hashes e reutilização segura quando implementada. Nunca apagar dados de usuário ou alterar originais.
- Sem distribuição de firmware, XVD/XVC proprietários, jogos, chaves, saves ou outras obras sem autorização. Não implementar contorno de DRM, extração de chaves ou bypass de proteções.
- Licença do código original: BSD-3-Clause. WinDurango é LGPL-3.0; revisar obrigações antes de reutilizar código. Azimuth é referência pública, não código-fonte disponível. Não importar dependências silenciosamente.
- Preservar diferenças entre os seis targets **planejados**: Windows x64/ARM64, Linux x64/ARM64 e macOS x64/ARM64. Um target compilando não demonstra funcionamento.

## Trabalho e testes dos agentes — regras permanentes

- Computer Use somente com autorização explícita. Testes visuais do sistema ou sessões prolongadas de jogos também exigem necessidade e autorização prévia.
- Não executar suítes completas automaticamente nem repetir testes aprovados sem mudança relevante. Preferir revisão documental, testes sintéticos e regressões focadas. Se um build falhar, não testar executáveis antigos.
- Processos em segundo plano exigem acompanhamento e duração limitada. Se uma interação exigir autorização não concedida, interromper essa interação e relatar a limitação.
- Concluir o escopo solicitado antes de abrir outra frente; não mascarar erros com stubs ou retornos de sucesso.
- Para cada mudança de código: reproduzir erro/contrato → implementar menor correção correta → testar somente a superfície afetada → registrar fatos, limitações e próximos bloqueios.
- Só publicar Release com autorização explícita. A atualização solicitada da `main` não autoriza mudar visibilidade, publicar builds nem reescrever o histórico existente.

## Commits e manutenção

- **Documentação:** desenvolvimento e evidências novas vão para `STATUS.md`, `docs/M*-STATUS.md` e `docs/NEXT-TASK.md`. Não editar READMEs, `AGENTS.md` ou `CLAUDE.md` por milestone. Só mudar documentos estáveis se a própria regra de produto, arquitetura permanente ou uso público mudar de verdade.

Usar Conventional Commits (`feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `build`, `ci`, `chore`). Não adicionar coautoria ou assinaturas atribuídas a assistentes, nem frases “Generated with…”; preservar licenças e créditos humanos reais. Commits diretos na `main` somente quando houver autorização para a tarefa e testes pertinentes. Não fazer force-push ou reescrever histórico publicado. Evitar arquivos e relatórios duplicados; atualizar a fonte canônica.

**Arquivos principais:** `README.md` (EN), `README.pt-BR.md` (PT-BR), `STATUS.md` (evidência atual), `docs/M0.md` (decisão técnica e próximo bloqueio), `docs/README.md` (índice), `CLAUDE.md` (instruções detalhadas). README e STATUS devem descrever somente o que foi demonstrado.
