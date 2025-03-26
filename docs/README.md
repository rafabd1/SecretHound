# SecretHound

SecretHound é uma ferramenta CLI desenvolvida em Go para extração de segredos de arquivos JavaScript.

## Características

- Extração de segredos via expressões regulares
- Processamento multi-thread de URLs
- Sistema inteligente para evitar bloqueios, rate limiting e WAF
- Cliente HTTP robusto com gerenciamento de retries e timeout
- Agrupamento de URLs por domínio para otimizar requisições
- Log colorido e formatado de forma intuitiva
- Escrita em tempo real dos segredos encontrados

## Instalação

```bash
# Clonando o repositório
git clone https://github.com/your-username/secrethound.git
cd secrethound

# Instalando as dependências
go mod download

# Compilando
go build -o secrethound
```

## Uso Básico

```bash
# Escaneando uma única URL
./secrethound scan https://example.com/script.js

# Escaneando múltiplas URLs
./secrethound scan https://example.com/script1.js https://example.com/script2.js

# Escaneando a partir de um arquivo com lista de URLs
./secrethound scan -i urls.txt -o resultados.json

# Ativando modo verbose para logs detalhados
./secrethound scan -i urls.txt -v
```

## Configuração

A ferramenta pode ser configurada por meio de flags:

```bash
# Ajuste de timeout (em segundos)
./secrethound scan -i urls.txt -t 60

# Configuração do número de workers concorrentes
./secrethound scan -i urls.txt -n 20

# Definição de arquivo de saída
./secrethound scan -i urls.txt -o resultados.json

# Limitação de taxa de requisições por domínio
./secrethound scan -i urls.txt -l 5

# Número máximo de retentativas em caso de falha
./secrethound scan -i urls.txt -r 5

# Uso de arquivo de regexes customizado
./secrethound scan -i urls.txt --regex-file minhas-regexes.txt
```

## Padrões de Regex

Por padrão, o SecretHound usa os padrões de regex embutidos para detectar segredos. 
Estes padrões estão definidos no código e cobrem mais de 50 tipos diferentes de segredos.

Se você quiser usar seus próprios padrões, você pode criar um arquivo de texto com o formato a seguir
e usá-lo com a flag `--regex-file`:

```
REGEX_PATTERNS = {
    "nome_do_padrao": "expressao_regular",
    "outro_padrao": "outra_expressao_regular"
}
```

Exemplo:

```
REGEX_PATTERNS = {
    "aws_key": "AKIA[0-9A-Z]{16}",
    "password": "(?i)password['\"]?\\s*[:=]\\s*['\"]([^'\"]+)['\"]"
}
```

Um arquivo de exemplo está disponível em `examples/regex.txt`.

## Padrões Suportados

SecretHound pode detectar dezenas de tipos diferentes de segredos, incluindo:

- Chaves de API (Google, AWS, Firebase, etc.)
- Tokens de acesso (Facebook, Twitter, GitHub, etc.)
- Credenciais (senhas, tokens Basic e Bearer)
- Chaves privadas (RSA, SSH, PGP)
- Tokens JWT
- URLs sensíveis (Firebase, AWS S3)
- E muito mais!

Para ver a lista completa de regexes suportadas, consulte o arquivo `regex.txt`.

## Licença

Este projeto está licenciado sob a licença MIT - consulte o arquivo LICENSE para obter detalhes.
