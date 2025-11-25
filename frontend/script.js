let token = "";

async function login(){
  const email = document.getElementById("email").value;
  const senha = document.getElementById("senha").value;

  const r = await fetch("http://localhost:3000/login",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({email,senha})
  });

  const dados = await r.json();
  token = dados.token;
  alert("Logado!");
}
