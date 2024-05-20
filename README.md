# UBI - Segurança de Sistemas Informáticos: TUDOIGUAL

Este repositório contém um projeto relacionado à segurança da informação. Esta aplicação CLI fornece funcionalidades para comunicação segura, encriptação e decriptação de ficheiros, assinatura digital e monitorização de diretórios para alterações. Utiliza click para a CLI, watchdog para monitorização de diretórios e cryptography para encriptação e assinaturas digitais.

## Requisitos

- Python 3.x

## Instalação

1. Clone este repositório:

   ```sh
   git clone https://github.com/juscelior/ubi-security-tudoigual.git
   ```

2. Navegue até o diretório do projeto:

    ```sh
    cd ubi-security-tudoigual
    ```

3. Instale as dependências necessárias:

    ```sh
    pip install -r requirements.txt
    ```

## Como Usar

A aplicação CLI possui vários comandos para iniciar o servidor, iniciar o cliente, decriptar ficheiros e executar testes.

### Iniciar Servidor

Inicia o servidor seguro e um watchdog para monitorizar um diretório especificado.

```sh
python cli.py start-server --host localhost --port 65432 --private-key-file private_server_key.pem --public-key-file public_server_key.pem --password --watch-path ./share-server --key-path ./k-server
```

Opções:

* __--host:__ Host do servidor (default: localhost).
* __--port:__ Porta do servidor (default: 65432).
* __--private-key-file:__ Caminho para o ficheiro da chave privada (default: private_server_key.pem).
* __--public-key-file:__ Caminho para o ficheiro da chave pública (default: public_server_key.pem).
* __--password:__ Palavra-passe para a chave privada.
* __--watch-path:__ Diretório para monitorizar com o Watchdog (default: ./share-server).
* __--key-path:__ Diretório para guardar as chaves (default: ./k-server).

### Iniciar Cliente

Inicia o cliente seguro e um watchdog para monitorizar um diretório especificado.

```sh
python cli.py start-client --server-host localhost --server-port 65432 --private-key-file private_client_key.pem --public-key-file public_client_key.pem --password --watch-path ./share-client
```

Opções:

* __--server-host:__ Host do servidor (default: localhost).
* __--server-port:__ Porta do servidor (default: 65432).
* __--private-key-file:__ Caminho para o ficheiro da chave privada (default: private_client_key.pem).
* __--public-key-file:__ Caminho para o ficheiro da chave pública (default: public_client_key.pem).
* __--password:__ Palavra-passe para a chave privada.
* __--watch-path:__ Diretório para monitorizar com o Watchdog (default: ./share-client).

## Decriptar Ficheiro

Decripta um ficheiro especificado e imprime o seu conteúdo original.

```sh
python cli.py decrypt --file_path ./share-server/teste.txt.enc --private-key-file private_client_key.pem --password
```

Opções:
* __--file_path:__ Caminho para o ficheiro encriptado (default: ./share-server/teste.txt.enc).
* __--private-key-file:__ Caminho para o ficheiro da chave privada (default: private_client_key.pem).
* __--password:__ Palavra-passe para a chave privada.

## Teste

Executa um teste para gerar chaves, encriptar um ficheiro, decriptar o ficheiro, assinar o ficheiro e verificar a assinatura.

```sh
python cli.py test
```

## Descrição das Funções Utilitárias

* __generate_keys(private_key_file, public_key_file, password):__ Gera um novo par de chaves RSA e guarda-as nos ficheiros especificados.
* __encrypt_file(filename, public_key_file):__ Encripta o ficheiro especificado usando a chave pública.
* __decrypt_file(encrypted_filename, private_key_file, password, encrypted_key):__ Decripta o ficheiro encriptado especificado usando a chave privada e a chave encriptada.
* __sign_file(filename, private_key_file, password):__ Assina o ficheiro especificado usando a chave privada.
* __verify_signature(filename, public_key_file, signature_file):__ Verifica a assinatura do ficheiro especificado usando a chave pública.


## Contribuição

1. Faça um fork do projeto.
2. Crie uma branch para a sua feature (git checkout -b feature/nova-feature).
3. Commit suas mudanças (git commit -am 'Adiciona nova feature').
4. Faça o push para a branch (git push origin feature/nova-feature).
5. Abra um Pull Request.

## Licença
Este projeto está licenciado sob a licença MIT. Veja o arquivo LICENSE para mais detalhes.

## Contato
Para qualquer dúvida ou sugestão, sinta-se à vontade para entrar em contato.


