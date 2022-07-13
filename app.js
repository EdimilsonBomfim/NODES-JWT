//iniciando/importando as dependencias instaladas
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose') 
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken') 

const app = express() //dea inicio aos endpoint/rotas/builder

//Configurar para aceitar Json como response
app.use(express.json());

//Importar entidades da Models
const User = require('./models/User')

//public Router
//Testando escuta da API - Rota inicial / Endpoint
app.get('/', (req, res) =>{
    // mostrar requisicao
    res.status(200).json({ mensagem: 'Bem vindo a nossa api de teste !' })
})

//Private Route - 
//Primeiro criando como public
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id

  //Chec se usuario existe - Busca por id
  const user = await User.findById(id, '-password')
  if( !user) {
    return res.status(404).json({mensagem: 'Usuario não encontrado'})
  }

  res.status(200).json({user})

})

function checkToken(req, res, next){
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(" ")[1]

  if(!token){
    return res.status(401).json({ mensagem: 'acesso negado'})
  }

  try{
    const secret = process.env.SECRET
    
    jwt.verify(token, secret)
    
    next()



  } catch(error){
    res.status(401).json({ mensagem: 'Token Invalido '})

  }
}



//Registrar Usuario
app.post('/auth/register', async(req, res) =>{

  const { name, email, password, confirmapassword} = req.body

  //Validar dados de entrada 
  if(!name){
    return res.status(422).json({mensagem: 'O nome é obrigatorio'})
  }

  if(!email){
    return res.status(422).json({mensagem: 'O email é obrigatorio'})
  }

  if(!password){
    return res.status(422).json({mensagem: 'O senha é obrigatorio! '})
  }
  
  if(password != confirmapassword){
    return res.status(422).json({mensagem: 'As senha não conferem! '})
  }

  //Checar se usuario exite - por email
  const userExists = await User.findOne({ email: email})
  if( userExists){
    return res.status(422).json({mensagem: 'Email já cadastrado.Por favor utilize outro endereço de e-mail !'})
  }

  //Create password com segurança
  const salt = await bcrypt.genSalt(12)
  const passwordHash = await bcrypt.hash(password, salt)
  
  //Create user
  const user = new User({
    name,
    email,
    password: passwordHash,
  })

  try {

    await user.save()
    res.status(201).json({mensagem: 'usuario criado com sucesso!'})

  } catch(error){
    console.log(error)
    res.status(500).json({ mensagem: 'erro de acesso ao servidor.Tente mais tarde!' })
  }
})


//Login para autenticação 
app.post('/auth/login', async( req,res) =>{

  const { email, password} = req.body
  //Validar
  if(!email){
    return res.status(422).json({mensagem: 'O email é obrigatorio'})
  }

  if(!password){
    return res.status(422).json({mensagem: 'O senha é obrigatorio! '})
  }

  //Checar se usuario existe
  const user = await User.findOne({email: email})
  if( !user){
    return res.status(404).json({mensage: 'Usuario informado não encontrado!'})
  }


   // check if password match
   const checkPassword = await bcrypt.compare(password, user.password );
   const tsecret = process.env.SECRET;
   console.log(user.password)
   console.log(password)
   console.log(tsecret)
   console.log(checkPassword)
   
   
   if (!checkPassword) {
     return res.status(422).json({ msg: "Senha inválida" });
   }

  try {
    const secret = process.env.SECRET;

    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );

    res.status(200).json({ msg: "Autenticação realizada com sucesso!", token });
  } catch (error) {
    res.status(500).json({ mensagem: 'erro de acesso ao servidor. tente mais tarde!'})
  }

})


//Fazendo chamada/referencia  para credenciais de banco
const dbuser= process.env.DB_USER
const dbpassword = process.env.DB_PASS


mongoose.connect(
    `mongodb+srv://${dbuser}:${dbpassword}@cluster0.ikpxi7v.mongodb.net/userApi?retryWrites=true&w=majority`
).then(() => {
    app.listen(3000)
    console.log("Conectado no banco com sucesso!")

}).catch((error) => console.log(error))
 

