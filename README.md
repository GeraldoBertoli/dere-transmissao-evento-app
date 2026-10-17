# DeRE Desktop

Aplicação desktop em Java 21, Maven e Swing para preparar e acompanhar lotes de eventos DeRE.

## Executar

```bash
mvn package
java -jar target/dere-desktop-1.0.0.jar
```

O Maven precisa conseguir baixar FlatLaf e Jackson na primeira compilação.

## Fluxo

1. Importe um ou mais XMLs de eventos.
2. Assine os eventos com um certificado PKCS#12. A senha é solicitada nessa etapa e não é gravada.
3. Valide os eventos assinados contra os XSDs fornecidos.
4. Monte o envelope do lote, informe o CNPJ e escolha onde salvar o XML.
5. Transmita o lote e guarde o protocolo retornado.
6. Na aba Protocolos, consulte o processamento e salve o retorno e os recibos encontrados.

As ações são separadas de propósito para permitir revisar cada resultado antes da próxima etapa. A API documentada de Produção Restrita usa `https://api.receitafederal.gov.br/prr-dere`; o manual fornecido não informa a URL base da API DeRE em Produção. Confirme a URL oficial e configure-a em Parâmetros antes de selecionar esse ambiente.

Na tela Eventos e transmissão, a fila mostra o estado de cada XML (importado, assinado, válido, incluído no lote e resultado da consulta), o estado do lote/protocolo e um histórico das ações recentes. A fila e o histórico ficam salvos para continuar acompanhando após reabrir a aplicação.

## Dados locais

As credenciais e configurações ficam em `~/.dere-desktop/config.json`; protocolos e retornos ficam em `~/.dere-desktop/protocolos.json` e `~/.dere-desktop/retornos/`. Em sistemas POSIX, a aplicação restringe a pasta para o usuário atual e o arquivo de configuração para leitura e gravação pelo proprietário. O client secret permanece armazenado localmente para permitir novas consultas e transmissões.

Os certificados por empresa são cadastrados em Parâmetros. A tela de assinatura permite escolher o certificado para cada execução. Os XSDs utilizados ficam no classpath da aplicação e correspondem aos arquivos de produção entregues com o projeto.
