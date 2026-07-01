const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const prisma = new PrismaClient();

async function main() {
  const senhaCriptografada = await bcrypt.hash('123456', 10);

  await prisma.user.upsert({
    where: { email: 'admin@escola.com' },
    update: {},
    create: { 
      email: 'admin@escola.com', 
      password: senhaCriptografada, 
      role: 'ADMIN' 
    },
  });

  await prisma.user.upsert({
    where: { email: 'usuario@escola.com' },
    update: {},
    create: { 
      email: 'usuario@escola.com', 
      password: senhaCriptografada, 
      role: 'USER' 
    },
  });

  console.log('Usuários de teste criados com sucesso!');
}

main()
  .catch((e) => console.error(e))
  .finally(async () => await prisma.$disconnect());