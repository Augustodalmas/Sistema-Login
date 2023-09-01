import sqlite3
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import hashlib
import json

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=FUTURO=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=#
# IMPLEMENTAÇÃO DO CRUD dentro da função perfil

# Achar metodo de fechar janelas anteriores.
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=GUI=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=#


class TelaInicial:
    def __init__(self, root) -> None:
        self.root = root
        self.root.title("Sistema de Login")

        # Utilizado quando APP é inicializado como .EXE para conectar ao banco de dados
        with open('config.json') as config_file:
            config = json.load(config_file)

        self.database = config["database"]
        self.conecta_banco = sqlite3.connect(self.database)
        self.criar_tabela()

        self.botao = ttk.Button(
            self.root, text="Registrar", command=self.adicionar_usuario
        )
        self.botao.pack(fill="x", expand=True)

        self.botao = ttk.Button(
            self.root, text="Logar", command=self.login
        )
        self.botao.pack(fill="x", expand=True)

        self.mostrar_senha = tk.BooleanVar()
        self.mostrar_senha.set(False)


# Função para mudar visibilidade da senha

    def toggle_password_visibility(self):
        if self.mostrar_senha.get():
            self.entrada_senha.config(show="")
        else:
            self.entrada_senha.config(show="•")


# Função para Criptografar senhas

    def criptografar_senha(self, senha):
        return hashlib.sha256(senha.encode()).hexdigest()


# Função para adicionar usuarios


    def adicionar_usuario(self):
        nova_janela = tk.Toplevel(root)
        nova_janela.title("")
        nova_janela.geometry("200x200")

        self.texto_usuario = ttk.Label(
            nova_janela, text="Usuario")
        self.texto_usuario.pack()

        self.entrada_usuario = ttk.Entry(nova_janela)
        self.entrada_usuario.pack()

        self.texto_email = ttk.Label(
            nova_janela, text="E-mail")
        self.texto_email.pack()

        self.entrada_email = ttk.Entry(nova_janela)
        self.entrada_email.pack()

        self.texto_senha = ttk.Label(nova_janela, text="Senha:")
        self.texto_senha.pack()

        self.entrada_senha = ttk.Entry(nova_janela, show="•")
        self.entrada_senha.pack()

        mostrar_senha_botao = ttk.Checkbutton(
            nova_janela, text="Mostrar Senha", variable=self.mostrar_senha, command=self.toggle_password_visibility
        )
        mostrar_senha_botao.pack()

        self.botao_adicionar = ttk.Button(
            nova_janela, text='Adicionar Usuario', command=lambda: (self.adicionar_user(), nova_janela.destroy())
        )
        self.botao_adicionar.pack(pady=5)

    def login(self):
        nova_janela = tk.Toplevel(root)
        nova_janela.title("")
        nova_janela.geometry("200x200")

        self.texto_usuario = ttk.Label(
            nova_janela, text="Usuario")
        self.texto_usuario.pack()

        self.entrada_usuario = ttk.Entry(nova_janela)
        self.entrada_usuario.pack()

        self.texto_senha = ttk.Label(nova_janela, text="Senha:")
        self.texto_senha.pack()

        self.entrada_senha = ttk.Entry(nova_janela, show="•")
        self.entrada_senha.pack()

        mostrar_senha_botao = ttk.Checkbutton(
            nova_janela, text="Mostrar Senha", variable=self.mostrar_senha, command=self.toggle_password_visibility
        )
        mostrar_senha_botao.pack()

        self.botao_adicionar = ttk.Button(
            nova_janela, text='Logar', command=lambda: (self.verificar_user(), nova_janela.destroy())
            # lambda cria um função anonima, que executar o verificar_user e após fecha a janela
        )
        self.botao_adicionar.pack(pady=5)

    # Perfil do usuario

    def perfil(self, user, passoword, id):
        self.perfil_usuario = user
        self.perfil_senha = passoword
        self.perfil_id = id

        nova_janela = tk.Toplevel(root)
        nova_janela.title("")
        nova_janela.geometry("350x200")

        self.texto_editar_usuario = ttk.Label(nova_janela, text="Novo Usuário")
        self.texto_editar_usuario.pack()

        self.entrada_editar_usuario = ttk.Entry(nova_janela)
        self.entrada_editar_usuario.pack()

        self.texto_editar_email = ttk.Label(nova_janela, text="Novo E-mail")
        self.texto_editar_email.pack()

        self.entrada_editar_email = ttk.Entry(nova_janela)
        self.entrada_editar_email.pack()

        self.texto_editar_senha = ttk.Label(nova_janela, text="Nova Senha")
        self.texto_editar_senha.pack()

        self.entrada_editar_senha = ttk.Entry(nova_janela, show="•")
        self.entrada_editar_senha.pack()

        mostrar_senha_botao = ttk.Checkbutton(
            nova_janela, text="Mostrar Senha", variable=self.mostrar_senha, command=self.toggle_password_visibility
        )
        mostrar_senha_botao.pack()

        self.mensagem_user = ttk.Label(
            nova_janela, text="Caixas em brancos será considerado informações anteriores!")
        self.mensagem_user.pack()

        self.editar_info = tk.Button(
            nova_janela, text="Editar Informações", command=lambda: (self.edit_info(), nova_janela.destroy())
        )
        self.editar_info.pack()

    # Mensagens ao Usuario

    def show_message(self):
        messagebox.showinfo("Mensagem", "Ação realizada com sucesso!")

    def show_erro(self):
        messagebox.showinfo("Mensagem", "Foi encontrado um erro!")


# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=Funções=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=#
# CRIAR TABELA

    def criar_tabela(self):
        try:
            comando = """
                    CREATE TABLE IF NOT EXISTS Usuarios(
                    ID INTEGER PRIMARY KEY,
                    Usuario TEXT,
                    Email TEXT,
                    Senha TEXT
                    )
                    """

            self.conecta_banco.execute(comando)
            self.conecta_banco.commit()

        except Exception as e:
            print("ERRO", e)
            self.show_erro()


# ADICIONAR NA TABELA


    def adicionar_user(self):
        try:
            usuario = self.entrada_usuario.get()
            email = self.entrada_email.get()
            senha = self.entrada_senha.get()
            senha_critografada = self.criptografar_senha(senha)

            cursor = self.conecta_banco.cursor()

            comando = """
                SELECT * FROM Usuarios
                WHERE Usuario = ?
                """
            cursor.execute(comando, (usuario,))
            self.resultado = cursor.fetchall()
            cursor.close()
            # Se usuario já cadastrado, dar mensagem de erro.
            if self.resultado:
                for usuario in self.resultado[0][1]:
                    messagebox.showerror(
                        'Mensagem', "Este usuario ja esta cadastrado!")
                    break
            else:

                comando = """
                    INSERT INTO Usuarios (Usuario, Email, Senha)
                    VALUES (?,?,?)
                    """
                self.conecta_banco.execute(
                    comando, (usuario, email, senha_critografada))
                self.conecta_banco.commit()
                self.entrada_usuario.delete(0, tk.END)
                self.entrada_senha.delete(0, tk.END)
                self.entrada_email.delete(0, tk.END)
                self.show_message()

        except Exception as e:
            print("ERRO", e)
            self.show_erro()

    def edit_info(self):
        try:
            # Dados
            id = self.perfil_id
            usuario = self.perfil_usuario
            senha = self.perfil_senha
            senha_criptograda = self.criptografar_senha(senha)
            novo_usuario = self.entrada_editar_usuario.get()
            nova_senha = self.entrada_editar_senha.get()
            nova_senha_criptografa = self.criptografar_senha(nova_senha)
            novo_email = self.entrada_editar_email.get()

            # Verificação de edição
            if novo_usuario == "":
                novo_usuario = usuario
            if nova_senha == "":
                nova_senha = senha
                nova_senha_criptografa = self.criptografar_senha(nova_senha)

            usuario = novo_usuario

            cursor = self.conecta_banco.cursor()

            comando_achar = """
                SELECT * FROM Usuarios
                WHERE id = ?
                """
            cursor.execute(comando_achar, (id,))
            self.resultado = cursor.fetchall()
            cursor.close()
            print(self.resultado)
            id = self.resultado[0][0]

            comando_editar = """
                UPDATE Usuarios
                SET Usuario = ?, Email = ?, Senha = ?
                    WHERE id = ?
                """
            self.conecta_banco.execute(
                comando_editar, (novo_usuario, novo_email, nova_senha_criptografa, id))
            self.conecta_banco.commit()
            print("Atualização feita com sucesso!")

            self.entrada_editar_usuario.delete(0, tk.END)
            self.entrada_editar_senha.delete(0, tk.END)
            self.entrada_editar_email.delete(0, tk.END)

        except Exception as e:
            print("ERRO", e)

# Verificar Usuario

    def verificar_user(self):
        try:
            usuario = self.entrada_usuario.get()
            senha = self.entrada_senha.get()
            senha_critografada = self.criptografar_senha(senha)

            cursor = self.conecta_banco.cursor()

            comando = """
                SELECT * FROM Usuarios
                WHERE Usuario = ?
                """
            cursor.execute(comando, (usuario,))
            self.resultado = cursor.fetchall()
            cursor.close()

            self.entrada_usuario.delete(0, tk.END)
            self.entrada_senha.delete(0, tk.END)

            id = self.resultado[0][0]

            # Verificador de usuario e senha.
            if self.resultado:
                if usuario == self.resultado[0][1] and senha_critografada == self.resultado[0][3]:
                    messagebox.showinfo("Mensagem", "Logado com Sucesso!!")
                    self.perfil(usuario, senha, id)
                else:
                    messagebox.showerror(
                        "Mensagem", "Usuario ou senha inválido")
            else:
                print("Erro ao acessar resultados!")

        except Exception as e:
            print("ERRO", e)


# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=Inicializador=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=#
if __name__ == "__main__":
    root = tk.Tk()
    app = TelaInicial(root)
    root.mainloop()
