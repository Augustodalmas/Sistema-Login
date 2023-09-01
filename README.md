O Sistema de Login é uma aplicação desenvolvida utilizando a linguagem de programação Python e as bibliotecas Tkinter e SQLite. Essa aplicação permite a criação de um ambiente seguro e controlado para autenticação de usuários, com o objetivo de garantir o acesso restrito a determinadas funcionalidades ou recursos. O sistema foi projetado para ser utilizado por aplicações que exigem autenticação, como plataformas web, aplicativos desktop ou serviços online.

Recursos Principais:

Interface Gráfica Intuitiva:
O sistema possui uma interface gráfica intuitiva desenvolvida com a biblioteca Tkinter, que oferece uma experiência amigável e fácil de usar para os usuários. A interface exibe campos de entrada para o usuário inserir seu nome de usuário e senha, bem como opções para criar um novo usuário.

Cadastro de Usuários:
O sistema permite que administradores ou usuários autorizados cadastrem novos usuários. Para cada novo usuário, são solicitados o nome de usuário, endereço de e-mail e senha. A senha é armazenada de forma criptografada no banco de dados para garantir a segurança das informações.

Autenticação Segura:
Ao tentar acessar recursos protegidos, os usuários são obrigados a fornecer suas credenciais (nome de usuário e senha) para autenticação. O sistema verifica se as informações fornecidas correspondem aos registros armazenados no banco de dados.

Proteção de Senhas:
As senhas dos usuários são armazenadas de forma segura por meio de técnicas de criptografia. Antes de serem armazenadas no banco de dados, as senhas são transformadas em hashes usando a função de hash SHA-256. Isso garante que as senhas originais não sejam armazenadas em texto simples.

Feedback ao Usuário:
O sistema fornece feedback visual ao usuário após tentativas de autenticação. Mensagens claras são exibidas para indicar se o login foi bem-sucedido ou se houve erros de credenciais.

Personalização:
O sistema oferece a possibilidade de personalizar a interface gráfica e as mensagens exibidas aos usuários, permitindo a integração perfeita com a identidade visual de outras aplicações.

Gerenciamento de Erros:
O sistema foi projetado para lidar com erros de forma adequada, exibindo mensagens de erro quando ocorrem problemas durante a autenticação ou outras operações.

Utilização de Banco de Dados:
O sistema utiliza um banco de dados SQLite para armazenar as informações dos usuários, como nomes de usuário, senhas criptografadas e outros detalhes. Isso permite um gerenciamento eficiente dos registros de usuários.
