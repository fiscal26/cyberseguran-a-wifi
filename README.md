# Wi-Fi Lab — laboratório de senhas WPA2

Ferramenta de linha de comando em português para demonstrar testes de dicionário, variações e combinações
**offline** contra PMKID de WPA2-Personal (PSK). Use nos testes das redes de vocês
ou com autorização do responsável. Requer Python 3.10 ou superior; não precisa
de bibliotecas extras, internet, placa Wi-Fi ou privilégios de administrador.

## Baixar e executar a demonstração

No terminal, com Git e Python instalados:

```bash
git clone https://github.com/fiscal26/cyberseguran-a-wifi.git
cd cyberseguran-a-wifi
python3 wifi_lab.py demo
```

O arquivo `examples/aula.22000` representa uma rede fictícia chamada `Aula-WiFi`.
A lista `examples/senhas.txt` contém quatro candidatas, incluindo `Aula2026!`.
A demonstração percorre a lista e verifica criptograficamente a correspondência.
Nenhuma rede é acessada e nenhuma captura é realizada.

Para demonstrar a descoberta de uma senha que **não aparece no arquivo de entrada**:

```bash
python3 wifi_lab.py demo --variations
```

Nesse exemplo, `examples/palavras.txt` contém apenas `aula` e `escola`. A ferramenta
gera `Aula2026!` a partir de `aula` e verifica a correspondência. Isso comprova o
funcionamento do exemplo; não garante descobrir a senha de qualquer rede.

Para atualizar uma cópia já baixada, execute `git pull` dentro da pasta do projeto.

## Testar um registro da própria rede

Forneça um registro PMKID já obtido no laboratório autorizado, exportado no
formato de texto hc22000. A aquisição desse registro depende do equipamento e
fica fora desta ferramenta. Crie a pasta `private` para manter os dados reais
fora do Git e coloque os dois arquivos nela:

```bash
mkdir -p private
python3 wifi_lab.py crack private/rede.22000 private/candidatas.txt
```

Uma frase-senha por linha no arquivo de candidatas. Para selecionar um nome de rede:

```bash
python3 wifi_lab.py crack private/rede.22000 private/candidatas.txt --ssid "Minha rede"
```

## Gerar variações das palavras

```bash
python3 wifi_lab.py crack private/rede.22000 private/palavras.txt --variations
```

O gerador testa a palavra original, minúsculas, primeira letra maiúscula,
maiúsculas e uma substituição de letras por números (`a/e/i/o/s/t` por
`4/3/1/0/5/7`). Para cada forma, acrescenta os sufixos fixos `""`, `123`, `123!`,
`!`, `2026` e `2026!`. Esses padrões são exemplos didáticos; o ano não muda
automaticamente. Repetições são removidas dentro de cada palavra, mantendo a
memória limitada. Repetições entre palavras diferentes podem ser testadas novamente.

É possível substituir os sufixos padrão; inclua `--suffix ""` para testar também
as formas sem sufixo:

```bash
python3 wifi_lab.py crack private/rede.22000 private/palavras.txt --variations --suffix "" --suffix "2027!"
```

## Testar combinações delimitadas

O comando `brute` gera combinações mesmo sem uma lista de palavras. É necessário
definir os caracteres e os comprimentos da parte variável. Prefixo e sufixo são
fixos e opcionais. O comprimento total deve permanecer entre 8 e 63 caracteres.

Exemplo pequeno que funciona com o registro fictício:

```bash
python3 wifi_lab.py brute examples/aula.22000 --charset "6!" --min-length 2 --max-length 2 --prefix Aula202
```

As quatro possibilidades são `Aula20266`, `Aula2026!`, `Aula202!6` e `Aula202!!`.
A senha é encontrada na segunda tentativa. O prefixo foi escolhido porque a
senha da demonstração é conhecida. Em uma rede real, uma hipótese errada de
prefixo, alfabeto ou comprimento pode excluir a senha correta da busca.

O total de combinações é exibido antes de começar. Com 10 caracteres possíveis
e 8 posições variáveis são **100 milhões de combinações**. Espaços maiores podem
ser impraticáveis; o tempo de execução depende da CPU e dos registros fornecidos.

## Limites, progresso e retomada

Cada execução processa no máximo **100.000 candidatas geradas**, incluindo as
inválidas. Modifique esse limite com `--limit`. A cada aproximadamente cinco
segundos, a ferramenta mostra progresso e velocidade média dos testes válidos,
sem exibir a candidata em teste.

Para salvar o progresso, use `--session`:

```bash
python3 wifi_lab.py crack private/rede.22000 private/palavras.txt --variations --limit 10000 --session private/aula.session.json
```

Depois de atingir o limite ou interromper com Ctrl+C, repita os mesmos parâmetros
e acrescente `--resume`:

```bash
python3 wifi_lab.py crack private/rede.22000 private/palavras.txt --variations --limit 10000 --session private/aula.session.json --resume
```

Pode-se mudar `--limit` na retomada. O conteúdo da captura e do dicionário, o filtro
de rede e as regras de geração devem permanecer iguais. A ferramenta compara
impressões SHA-256 para recusar uma retomada incompatível. Não edite os arquivos
durante a execução e use apenas um processo por arquivo de sessão.

A sessão é atualizada aproximadamente a cada cinco segundos e ao terminar ou
receber Ctrl+C. Um encerramento abrupto pode exigir repetir o trabalho desde o
último salvamento. Na retomada de dicionários, as linhas são relidas para localizar
a posição, sem repetir as verificações criptográficas já concluídas. Na busca de
combinações, a ferramenta vai diretamente à posição salva.

O arquivo de sessão guarda contadores, estado e uma impressão dos parâmetros;
não guarda a senha encontrada nem as palavras candidatas. Sessões concluídas
não são retomadas: para uma nova busca, escolha outro arquivo de sessão.

**Busca parcial** significa que o limite foi atingido com candidatas restantes.
**Nenhuma correspondência** significa que o conjunto configurado foi esgotado.
Nenhum desses resultados certifica a segurança da rede.

## Formato e resultados

Formato aceito, com os campos em hexadecimal:

```text
WPA*01*PMKID*MAC_AP*MAC_CLIENTE*SSID_HEX***
```

O arquivo pode conter múltiplos registros, linhas vazias e comentários iniciados
por `#`, inclusive comentários em português e arquivos UTF-8 com BOM. Registros
duplicados são eliminados. A busca termina na **primeira**
correspondência, exibindo a senha no terminal; cuidado ao projetar dados reais
durante a aula. Espaços nas frases-senha são preservados. Linhas com menos de 8
ou mais de 63 caracteres, ou caracteres fora do ASCII imprimível, são ignoradas.
O arquivo não precisa estar inteiro na memória; é lido linha a linha.

Códigos de saída: `0` = correspondência, `1` = conjunto esgotado sem correspondência,
`2` = erro de entrada ou de arquivo, `3` = busca parcial por limite,
`130` = interrupção com Ctrl+C.

## O que a aula demonstra

Para cada candidata, a ferramenta calcula:

1. `PMK = PBKDF2-HMAC-SHA1(senha, SSID, 4096, 32 bytes)`.
2. `PMKID = HMAC-SHA1(PMK, "PMK Name" || MAC_AP || MAC_CLIENTE)[:16]`.
3. Compara o resultado com o registro fornecido.

Não há tentativa de login no roteador. Uma candidata só funciona se produzir o
PMKID registrado. A senha precisa estar na lista ou ser produzida pelas regras
ou combinações configuradas para ser encontrada.
Resultado negativo não certifica segurança. O tempo mostrado é o tempo desta
execução em CPU, não uma estimativa de resistência a equipamentos especializados.

## Limitações

- Suporta somente PMKID WPA2-Personal calculado pela fórmula acima. A existência
  de um registro utilizável depende da implementação e configuração do AP.
- Não lê PCAP/PCAPNG nem registros EAPOL `WPA*02`; uma extensão `.22000` sozinha
  não garante que o conteúdo seja compatível.
- Não testa WPA3-SAE, WPA-Enterprise, WPS ou chaves PSK brutas de 64 dígitos hex.
- Não faz varredura, captura, desconexão de clientes, nem conexão à rede.
- Execução sequencial em CPU, adequada a listas pequenas em sala de aula.

Para discutir proteção: prefiram WPA3-Personal quando disponível, desativem WPS,
atualizem o roteador e usem frases-senha longas, exclusivas e pouco previsíveis.

## Verificar o projeto

```bash
python3 -m unittest discover -s tests -v
```

Não inclua capturas ou senhas reais no repositório; a pasta `private/` já está
no `.gitignore`.
