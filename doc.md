+--------------------------------------------------+
|                   Aplicação Cliente              |
+--------------------------------------------------+
|                                                  |
|  +--------------------------------------------+  |
|  |              Diretoria Local               |  |
|  +--------------------------------------------+  |
|                                                  |
|  +--------------------------------------------+  |
|  |  1. Monitorar Diretoria                    |  |
|  +--------------------------------------------+  |
|  |                                            |  |
|  |  2. Cifrar Ficheiro (AES)                  |  |
|  |                                            |  |
|  |  3. Calcular Assinatura Digital (SHA256)   |  |
|  |                                            |  |
|  |  4. Enviar Ficheiro Cifrado e Assinatura   |  |
|  |     ao Servidor                            |  |
|  |                                            |  |
|  +--------------------------------------------+  |
|                                                  |
+--------------------------------------------------+
                       |
                       |
                       v
+--------------------------------------------------+
|                      Servidor                    |
+--------------------------------------------------+
|                                                  |
|  +--------------------------------------------+  |
|  |  5. Receber Ficheiro Cifrado e Assinatura  |  |
|  +--------------------------------------------+  |
|  |                                            |  |
|  |  6. Armazenar Ficheiro e Assinatura        |  |
|  |                                            |  |
|  |  7. Notificar Outros Clientes              |  |
|  |                                            |  |
|  +--------------------------------------------+  |
|                                                  |
+--------------------------------------------------+
                       |
                       |
                       v
+--------------------------------------------------+
|                   Aplicação Cliente              |
+--------------------------------------------------+
|                                                  |
|  +--------------------------------------------+  |
|  |              Diretoria Local               |  |
|  +--------------------------------------------+  |
|  |                                            |  |
|  |  8. Receber Notificação do Servidor        |  |
|  |                                            |  |
|  |  9. Baixar Ficheiro Cifrado e Assinatura   |  |
|  |                                            |  |
|  | 10. Verificar Assinatura Digital           |  |
|  |                                            |  |
|  | 11. Decifrar Ficheiro (AES)                |  |
|  |                                            |  |
|  | 12. Sincronizar Diretoria Local            |  |
|  |                                            |  |
|  +--------------------------------------------+  |
|                                                  |
+--------------------------------------------------+


## Descrição do Fluxo

1. Monitorar Diretoria Local: O cliente monitora a diretoria local para mudanças.
2. Cifrar Ficheiro (AES): Quando um novo ficheiro é adicionado, ele é cifrado usando AES.
3. Calcular Assinatura Digital (SHA256): A assinatura digital do ficheiro é calculada usando SHA256.
4. Enviar Ficheiro Cifrado e Assinatura ao Servidor: O ficheiro cifrado e a assinatura digital são enviados ao servidor.
5. Receber Ficheiro Cifrado e Assinatura: O servidor recebe o ficheiro cifrado e a assinatura digital.
6. Armazenar Ficheiro e Assinatura: O servidor armazena o ficheiro cifrado e a assinatura digital.
7. Notificar Outros Clientes: O servidor notifica outros clientes sobre o novo ficheiro.
8. Receber Notificação do Servidor: O cliente recebe a notificação do servidor.
9. Baixar Ficheiro Cifrado e Assinatura: O cliente baixa o ficheiro cifrado e a assinatura digital.
10. Verificar Assinatura Digital: O cliente verifica a assinatura digital.
11. Decifrar Ficheiro (AES): O cliente decifra o ficheiro usando AES.
12. Sincronizar Diretoria Local: O cliente sincroniza a diretoria local com o novo ficheiro.

## Segurança

1. Criptografia: Utiliza AES para cifrar ficheiros antes da transmissão.
2. Assinatura Digital: Utiliza SHA256 para garantir a integridade dos ficheiros.
3. Autenticação: Os clientes e o servidor se autenticam mutuamente para garantir que estão se comunicando com as entidades corretas.

## Potenciais Vulnerabilidades

1. Intercepção de Chave Privada: Garantir que a chave privada nunca seja transmitida ou exposta.
2. Ataques Man-in-the-Middle: Usar protocolos seguros (e.g., TLS) para proteger contra interceptação de comunicação.
