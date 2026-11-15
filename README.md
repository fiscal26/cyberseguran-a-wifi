# Wi-Fi Lab — laboratório de senhas WPA2

Ferramenta de linha de comando em português para demonstrar testes de dicionário
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

Formato aceito, com os campos em hexadecimal:

```text
WPA*01*PMKID*MAC_AP*MAC_CLIENTE*SSID_HEX***
```

O arquivo pode conter múltiplos registros, linhas vazias e comentários iniciados
por `#`. Registros duplicados são eliminados. A busca termina na **primeira**
correspondência, exibindo a senha no terminal; cuidado ao projetar dados reais
durante a aula. Espaços nas frases-senha são preservados. Linhas com menos de 8
ou mais de 63 caracteres, ou caracteres fora do ASCII imprimível, são ignoradas.
O arquivo não precisa estar inteiro na memória; é lido linha a linha.

Códigos de saída: `0` = correspondência, `1` = lista esgotada sem correspondência,
`2` = erro de entrada, `130` = interrupção com Ctrl+C.

## O que a aula demonstra

Para cada candidata, a ferramenta calcula:

1. `PMK = PBKDF2-HMAC-SHA1(senha, SSID, 4096, 32 bytes)`.
2. `PMKID = HMAC-SHA1(PMK, "PMK Name" || MAC_AP || MAC_CLIENTE)[:16]`.
3. Compara o resultado com o registro fornecido.

Não há tentativa de login no roteador. Uma candidata só funciona se produzir o
PMKID registrado. Se a senha não estiver na lista, ela não será encontrada.
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
