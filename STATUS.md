# STATUS — xboxone-native

## 2026-11-04 — M0 publicado na `main`

- Repositório existente iniciado com CLI, biblioteca e testes C++20/CMake. Primeiro commit de documentação: `0edf8ca`; incremento funcional M0: `4ad22ab`.
- `inspect <file> [--json]` lê **sem copiar ou modificar** cabeçalhos XVD (metadados, sem validar assinatura ou descriptografar) e PE32+ AMD64 (características, DLLs e símbolos importados).
- Validação local inicial: build Linux concluído e **2 testes CTest aprovados** com fixtures sintéticas. O workflow GitHub Actions está configurado para Windows, Linux e macOS; a execução dos runners e todos os targets ARM64 **não estão certificados** por este registro.
- **Nenhum componente original do SystemOS foi executado.** Não existem primeira imagem, boot da dashboard, Guide, launcher gráfico, backend de GameOS, jogo executado, renderizador ou Release para usuários.
- Arquitetura provisória: inspeção e inventário compartilhados, fronteiras separadas de SystemOS e GameOS, execução x86-64 direta apenas onde viável e VM/híbrido quando necessário. Ver [docs/M0.md](docs/M0.md).

## Bloqueio atual

Para alcançar a primeira imagem autêntica, são necessários um componente original do SystemOS **legalmente legível** e seus recursos da mesma versão, mais um mapa de dependências (PE/WinRT/NT, pacote, composição, broker e dispositivos). O XVD reconhecido pelo inspetor não fornece esses componentes automaticamente.

**Próximo incremento previsto:** inventário recursivo somente leitura com SHA-256, identificação determinística de módulos aprovados, manifesto vinculado à versão e relatório das dependências realmente disponíveis/ausentes. Usar fixtures sintéticas para testar as regras sem distribuir material proprietário. Não simular a dashboard para obter uma imagem rápida.

**Regra de leitura:** status acima é evidência de ferramentas de inspeção, não compatibilidade de software Xbox One. Toda nova afirmação de boot, imagem ou jogabilidade precisa de teste real e versão/hash identificados.
