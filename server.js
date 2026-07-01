const express = require('express');
const bcrypt = require('bcrypt');
const { PrismaClient } = require('@prisma/client');
const path = require('path');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const prisma = new PrismaClient();
const app = express();

//A chave secreta deve ficar em variáveis de ambiente (.env) em produção
//const JWT_SECRET = process.env.JWT_SECRET
const JWT_SECRET = 'minha_chave_super_secreta_123';

app.use(express.json());
app.use(cookieParser()); //Necessário para ler os cookies que o navegador enviar
app.use(express.static(path.join(__dirname, 'public')));


//ROTA DE LOGIN (Gera o Token)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ error: 'Usuário não encontrado.' });

    const senhaValida = await bcrypt.compare(password, user.password);
    if (!senhaValida) return res.status(401).json({ error: 'Senha incorreta.' });

    //Cria o token com o ID e o Papel (Role) do usuário
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, {
      expiresIn: '1h' // O token expira em 1 hora
    });

    //Envia o token como um cookie HTTP-Only (não acessível via JavaScript no navegador)
    res.cookie('token', token, {
      httpOnly: true,
      secure: false, //Em produção (com HTTPS), esse valor é true (no nosso caso não vamos trabalhar com isso, então não alterem)
      maxAge: 3600000 //1 hora em milissegundos
    });

    res.json({ success: true, role: user.role });
    
  } catch (error) {
    res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

//MIDDLEWARE DE AUTENTICAÇÃO
function verificarAutenticacao(req, res, next) {
  const token = req.cookies.token; //Lê o token do cookie

  if (!token) {
    return res.status(403).send('Acesso Negado: Faça login para continuar.');
  }

  try {
    //Decodifica o token e anexa os dados do usuário na requisição
    const dadosUsuario = jwt.verify(token, JWT_SECRET);
    req.user = dadosUsuario; 
    next(); //Permite que a requisição siga em frente
  } catch (error) {
    return res.status(401).send('Token inválido ou expirado. Faça login novamente.');
  }
}

//ROTAS PROTEGIDAS (Servem as páginas HTML)
app.get('/admin', verificarAutenticacao, (req, res) => {
  //Verifica se a role bate com a exigida para esta página
  if (req.user.role !== 'ADMIN') {
    return res.status(403).send('Você não tem permissão de Administrador.');
  }
  //Só envia o arquivo HTML se o token for válido e o usuário for ADMIN
  res.sendFile(path.join(__dirname, 'private', 'admin.html'));
});

app.get('/user', verificarAutenticacao, (req, res) => {
  res.sendFile(path.join(__dirname, 'private', 'user.html'));
});

//ROTA DE LOGOUT (Limpa o Cookie)
app.get('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/'); //Redireciona para o index.html (Login)
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
