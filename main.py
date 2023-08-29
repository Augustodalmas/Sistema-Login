import sqlite3
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import hashlib
import json

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=FUTURO=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=#
# IMPLEMENTAÇÃO DO CRUD dentro da função perfil
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=GUI=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=#


class TelaInicial:
    def __init__(self, root) -> None:
        self.root = root
        self.root.title("Sistema de Login")

        with open('config.json') as config_file:
            config = json.load(config_file)
        self.database = config["database"]
        self.conecta_banco = sqlite3.connect(self.database)
        self.criar_tabela()

        self.frame_botao = tk.Frame(root)
        self.frame_botao.pack(side="left", padx=0, pady=0)
        self.botao = tk.Button(
            self.frame_botao, text="Registrar", command=self.adicionar_usuario
        )
        self.botao.pack(fill="x", expand=True)

        self.botao = tk.Button(
            self.frame_botao, text="Logar", command=self.login
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
            nova_janela, text='Adicionar Usuario', command=self.adicionar_user
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
            nova_janela, text='Logar', command=self.verificar_user
        )
        self.botao_adicionar.pack(pady=5)

    # Perfil do usuario

    def perfil(self, user, passoword, passoword_cripto):
        self.perfil_usuario = user
        self.perfil_senha = passoword
        self.perfil_senhaCripto = passoword_cripto
        nova_janela = tk.Toplevel(root)
        nova_janela.title("")
        nova_janela.geometry("200x200")

        self.editar_info = tk.Button(
            nova_janela, text="Editar Informações", command=self.edit_info
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
        except:
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

        except:
            self.show_erro()

    def edit_info(self):
        try:
            usuario = self.perfil_usuario
            senha = self.perfil_senha
            senha_cripto = self.perfil_senhaCripto

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
            print("Seu usuario é:" + usuario)
            print("Seu usuario é:" + senha)
            print("Seu usuario é:" + senha_cripto)

        except:
            print("ERRO")

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

            # Verificador de usuario e senha.
            if self.resultado:
                if usuario == self.resultado[0][1] and senha_critografada == self.resultado[0][3]:
                    messagebox.showinfo("Mensagem", "Logado com Sucesso!!")
                    self.perfil(usuario, senha, senha_critografada)
                else:
                    messagebox.showerror(
                        "Mensagem", "Usuario ou senha inválido")
            else:
                print("Erro ao acessar resultados!")

        except:
            print("ERRO")


# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=Inicializador=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=#
if __name__ == "__main__":
    root = tk.Tk()
    app = TelaInicial(root)
    root.mainloop()
