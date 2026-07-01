const express = require('express');
const bcrypt = require('bcrypt');
const { PrismaClient } = require('@prisma/client');
const path = require('path');

const prisma = new PrismaClient();
const app = express();

//Permite que o Express entenda JSON e sirva arquivos estáticos da pasta "public"
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    //Busca o usuário no banco
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: 'Usuário não encontrado.' });
    }

    //Compara a senha digitada com a criptografada no banco
    const senhaValida = await bcrypt.compare(password, user.password);
    if (!senhaValida) {
      return res.status(401).json({ error: 'Senha incorreta.' });
    }

    //Retorna sucesso e o tipo de usuário
    res.json({ success: true, role: user.role });
    
  } catch (error) {
    res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
