import sqlite3
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from tkinter import PhotoImage
import hashlib
import json

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=FUTURO=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=#
# Estilização e ajuste finais
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=GUI=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


class tela_inicial:
    def __init__(self, root, banco) -> None:
        self.root = root
        self.root.config(bg="#cfcfcf")
        root.geometry("350x200")
        self.root.title("Sistema de Login")
        self.banco_dados = banco
        self.banco_dados.criar_tabela(self)

        # Estilização

        # self.imagem = PhotoImage(file=r"Imagens/Usuario.png")
        # self.imagem_usuario = ttk.Label(root, image=self.imagem, width=20)
        # self.imagem_usuario.pack()""

        self.botao = tk.Button(
            self.root, text="Registrar", command=self.adicionar_usuario)

        self.botao.pack(fill="x", expand=True, padx=1, side=tk.LEFT)

        self.botao = tk.Button(self.root, text="Logar", command=self.login)
        self.botao.pack(fill="x", expand=True, side=tk.RIGHT)

        self.mostrar_senha = tk.BooleanVar()
        self.mostrar_senha.set(False)

        # Centralização de tela
        largura_tela = root.winfo_screenwidth()
        altura_tela = root.winfo_screenheight()

        x = (largura_tela - root.winfo_reqwidth()) / 2
        y = (altura_tela - root.winfo_reqheight()) / 2

        root.geometry("+%d+%d" % (x, y))


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
        nova_janela.title("Tela de registro")
        nova_janela.geometry("350x200")

        self.texto_usuario = ttk.Label(
            nova_janela, text="usuário")
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
            nova_janela, text='Adicionar usuário', command=lambda: (self.banco_dados.adicionar_user(self), nova_janela.destroy())
        )
        self.botao_adicionar.pack(pady=5)

        # Centralização de tela
        largura_tela = nova_janela.winfo_screenwidth()
        altura_tela = nova_janela.winfo_screenheight()

        x = (largura_tela - nova_janela.winfo_reqwidth()) / 2
        y = (altura_tela - nova_janela.winfo_reqheight()) / 2

        nova_janela.geometry("+%d+%d" % (x, y))

    def login(self):
        nova_janela = tk.Toplevel(root)
        nova_janela.title("Tela de login")
        nova_janela.geometry("350x200")

        self.texto_usuario = ttk.Label(
            nova_janela, text="usuário")
        self.texto_usuario.pack()

        self.entrada_usuario = ttk.Entry(nova_janela)
        self.entrada_usuario.pack()

        self.texto_senha = ttk.Label(nova_janela, text="Senha:")
        self.texto_senha.pack()

        self.entrada_senha = ttk.Entry(nova_janela, show="•")
        self.entrada_senha.pack()

        mostrar_senha_botao_login = ttk.Checkbutton(
            nova_janela, text="Mostrar Senha", variable=self.mostrar_senha, command=self.toggle_password_visibility
        )
        mostrar_senha_botao_login.pack()

        self.botao_adicionar = ttk.Button(
            nova_janela, text='Logar', command=lambda: (self.banco_dados.verificar_user(self, nova_janela))
            # lambda cria um função anonima, que executar o verificar_user e após fecha a janela
        )
        self.botao_adicionar.pack(pady=5)

        # Centralização de tela
        largura_tela = nova_janela.winfo_screenwidth()
        altura_tela = nova_janela.winfo_screenheight()

        x = (largura_tela - nova_janela.winfo_reqwidth()) / 2
        y = (altura_tela - nova_janela.winfo_reqheight()) / 2

        nova_janela.geometry("+%d+%d" % (x, y))

    # Perfil do usuario

    def perfil(self, user, passoword, email, id):
        self.perfil_usuario = user
        self.perfil_senha = passoword
        self.perfil_id = id
        self.perfil_email = email

        nova_janela = tk.Toplevel(root)
        nova_janela.title("Perfil usuário")
        nova_janela.geometry("350x200")

        self.editar_info = ttk.Button(nova_janela, text="Editar Informações", command=lambda: self.atualizar_usuario(
            self.perfil_usuario, self.perfil_senha, self.perfil_id, self.perfil_email))
        self.editar_info.pack(fill="x", expand=True, side=tk.LEFT)

        self.editar_info = ttk.Button(nova_janela, text="Excluir Usuario", command=lambda: (self.banco_dados.excluir_user(
            self, self.perfil_id), nova_janela.destroy()))
        self.editar_info.pack(fill="x", expand=True, side=tk.RIGHT)

        # Centralização de tela
        largura_tela = nova_janela.winfo_screenwidth()
        altura_tela = nova_janela.winfo_screenheight()

        x = (largura_tela - nova_janela.winfo_reqwidth()) / 2
        y = (altura_tela - nova_janela.winfo_reqheight()) / 2

        nova_janela.geometry("+%d+%d" % (x, y))

    def atualizar_usuario(self, user, passoword, id, email):
        self.perfil_usuario = user
        self.perfil_senha = passoword
        self.perfil_id = id
        self.perfil_email = email

        nova_janela = tk.Toplevel(root)
        nova_janela.title("Editar Informações")
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

        self.entrada_editar_senha = ttk.Entry(nova_janela)
        self.entrada_editar_senha.pack()

        self.mensagem_user = ttk.Label(
            nova_janela, text="Caixas em brancos serão consideradas informações anteriores!")
        self.mensagem_user.pack()

        self.editar_info = ttk.Button(
            nova_janela, text="Editar Informações", command=lambda: (self.banco_dados.edit_user(self, self.perfil_usuario, self.perfil_senha, self.perfil_id, self.perfil_email), nova_janela.destroy())
        )
        self.editar_info.pack()

        largura_tela = nova_janela.winfo_screenwidth()
        altura_tela = nova_janela.winfo_screenheight()

        x = (largura_tela - nova_janela.winfo_reqwidth()) / 2
        y = (altura_tela - nova_janela.winfo_reqheight()) / 2

        nova_janela.geometry("+%d+%d" % (x, y))

    # Mensagens ao Usuario

    def show_message(self):
        messagebox.showinfo("Mensagem", "Ação realizada com sucesso!")

    def show_erro(self):
        messagebox.showinfo("Mensagem", "Foi encontrado um erro!")


# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=Funções=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=#
class banco_manage:
    def __init__(self, tela):
        self.tela = tela
        # Utilizado quando APP é inicializado como .EXE para conectar ao banco de dados
        with open('config.json') as config_file:
            config = json.load(config_file)
        self.database = config["database"]
        self.conecta_banco = sqlite3.connect(self.database)

    # CRIAR TABELA
    def criar_tabela(self, tela):
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
            tela.show_erro()


# ADICIONAR NA TABELA


    def adicionar_user(self, tela):
        try:
            usuario = tela.entrada_usuario.get()
            email = tela.entrada_email.get()
            senha = tela.entrada_senha.get()
            senha_critografada = tela.criptografar_senha(senha)

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
                tela.entrada_usuario.delete(0, tk.END)
                tela.entrada_senha.delete(0, tk.END)
                tela.entrada_email.delete(0, tk.END)
                tela.show_message()

        except Exception as e:
            print("ERRO", e)
            tela.show_erro()

    def edit_user(self, tela, usuario, senha, id, email):
        try:
            # Dados
            # senha_criptograda = tela.criptografar_senha(senha)
            novo_usuario = tela.entrada_editar_usuario.get()
            nova_senha = tela.entrada_editar_senha.get()
            nova_senha_criptografa = tela.criptografar_senha(nova_senha)
            novo_email = tela.entrada_editar_email.get()

            # Verificação de edição
            if novo_usuario == "":
                novo_usuario = usuario
            if nova_senha == "":
                nova_senha = senha
                nova_senha_criptografa = tela.criptografar_senha(nova_senha)
            if novo_email == "":
                novo_email = email

            usuario = novo_usuario

            cursor = self.conecta_banco.cursor()

            comando_achar = """
                SELECT * FROM Usuarios
                WHERE id = ?
                """
            cursor.execute(comando_achar, (id,))
            self.resultado = cursor.fetchall()
            cursor.close()
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

            tela.entrada_editar_usuario.delete(0, tk.END)
            tela.entrada_editar_senha.delete(0, tk.END)
            tela.entrada_editar_email.delete(0, tk.END)

        except Exception as e:
            print(e)

    def excluir_user(self, tela, id):
        self.remover_id = id

        comando_excluir = """
            DELETE FROM Usuarios
            WHERE id = ?
            """
        try:
            self.conecta_banco.execute(comando_excluir, (id,))
            self.conecta_banco.commit()
            tela.show_message()

        except Exception as e:
            tela.show_erro()
            print(e)
# Verificar Usuario

    def verificar_user(self, tela, nova_janela):
        try:
            usuario = tela.entrada_usuario.get()
            senha = tela.entrada_senha.get()
            senha_critografada = tela.criptografar_senha(senha)
            janela = nova_janela

            cursor = self.conecta_banco.cursor()

            comando = """
                SELECT * FROM Usuarios
                WHERE Usuario = ?
                """
            cursor.execute(comando, (usuario,))
            self.resultado = cursor.fetchall()
            cursor.close()

            tela.entrada_usuario.delete(0, tk.END)
            tela.entrada_senha.delete(0, tk.END)

            id = self.resultado[0][0]
            email = self.resultado[0][2]

            # Verificador de usuario e senha.
            if self.resultado:
                if usuario == self.resultado[0][1] and senha_critografada == self.resultado[0][3]:
                    messagebox.showinfo("Mensagem", "Logado com Sucesso!!")
                    janela.destroy()
                    tela.perfil(usuario, senha, email, id)
                else:
                    messagebox.showerror(
                        "Mensagem", "Usuario ou senha inválido")
            else:
                print("Erro ao acessar resultados!")

        except Exception as e:
            messagebox.showerror(
                "Mensagem", "Usuario ou senha inválido")
            print("ERRO", e)


# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=Inicializador=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=#
if __name__ == "__main__":
    root = tk.Tk()
    banco = banco_manage(None)
    app = tela_inicial(root, banco)
    root.mainloop()
