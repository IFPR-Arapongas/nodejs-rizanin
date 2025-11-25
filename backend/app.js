// API Node.js com Express + MySQL (MariaDB)
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');
require('dotenv').config();

const app = express();
app.use(express.json());

// Conexão com banco
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
});

// Middleware de autenticação
function auth(req,res,next){
  const header = req.headers.authorization;
  if(!header) return res.status(401).json({erro:"Token ausente"});
  const token = header.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err,decoded)=>{
    if(err) return res.status(401).json({erro:"Token inválido"});
    req.userId = decoded.id;
    next();
  });
}

// Cadastro
app.post("/cadastro", async (req,res)=>{
  const {nome,email,senha} = req.body;
  const hash = await bcrypt.hash(senha,10);
  await db.query("INSERT INTO usuarios (nome,email,senha) VALUES (?,?,?)",[nome,email,hash]);
  res.json({mensagem:"Usuário criado"});
});

// Login
app.post("/login", async (req,res)=>{
  const {email,senha} = req.body;
  const [user] = await db.query("SELECT * FROM usuarios WHERE email=?",[email]);
  if(user.length===0) return res.status(400).json({erro:"Usuário não encontrado"});
  const ok = await bcrypt.compare(senha, user[0].senha);
  if(!ok) return res.status(400).json({erro:"Senha errada"});
  const token = jwt.sign({id:user[0].id}, process.env.JWT_SECRET,{expiresIn:"1d"});
  res.json({token});
});

// CRUD de tarefas
app.post("/tarefas", auth, async (req,res)=>{
  const {titulo,status} = req.body;
  await db.query("INSERT INTO tarefas (usuario_id,titulo,status) VALUES (?,?,?)",[req.userId,titulo,status]);
  res.json({mensagem:"Tarefa criada"});
});

app.get("/tarefas", auth, async (req,res)=>{
  const [rows] = await db.query("SELECT * FROM tarefas WHERE usuario_id=?",[req.userId]);
  res.json(rows);
});

app.put("/tarefas/:id", auth, async (req,res)=>{
  const {titulo,status} = req.body;
  await db.query("UPDATE tarefas SET titulo=?,status=? WHERE id=? AND usuario_id=?",[titulo,status,req.params.id,req.userId]);
  res.json({mensagem:"Atualizada"});
});

app.delete("/tarefas/:id", auth, async (req,res)=>{
  await db.query("DELETE FROM tarefas WHERE id=? AND usuario_id=?",[req.params.id,req.userId]);
  res.json({mensagem:"Removida"});
});

app.listen(process.env.PORT,()=>console.log("API rodando"));
