(() => {
  const $ = id => document.getElementById(id);
  let csrfToken = null;
  const apiBase = () => String(window.DO_ZERO_SA_API_URL || "").trim().replace(/\/+$/, "");
  const status = (id, msg, error=false) => { const el=$(id); if(el){el.textContent=msg;el.style.color=error?"#ffb3a8":"#a2adbd";} };
  async function api(path, options={}) {
    const base=apiBase();
    if(!base) throw new Error("A API segura ainda não foi configurada. O login remoto está indisponível.");
    const headers=new Headers(options.headers||{});
    if(csrfToken && options.method && options.method!=="GET") headers.set("X-CSRF-Token",csrfToken);
    const res=await fetch(base+path,{...options,headers,credentials:"include"});
    const data=await res.json().catch(()=>({}));
    if(!res.ok) throw new Error(data.error||("Falha na API ("+res.status+")."));
    return data;
  }
  function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
  function bytes(n){return n<1048576?Math.round(n/1024)+" KB":(n/1048576).toFixed(1)+" MB";}
  function showWorkspace(){ $("loginPanel").classList.add("hidden"); $("workspace").classList.remove("hidden"); refresh(); }
  async function refresh(){
    try{
      const [a,p]=await Promise.all([api("/api/assets"),api("/api/projects")]);
      $("assets").innerHTML=a.items.length?a.items.map(x=>'<div class="item"><strong>'+esc(x.original_name)+'</strong><br><span class="muted">'+bytes(x.size_bytes)+' · '+new Date(x.created_at).toLocaleString("pt-BR")+'</span> <button class="btn" data-download="'+esc(x.id)+'" type="button">Baixar</button> <button class="btn" data-delete="'+esc(x.id)+'" type="button">Excluir</button></div>').join(""):'<p class="muted">Ainda não há materiais no servidor.</p>';
      $("projects").innerHTML=p.items.length?p.items.map(x=>'<div class="item"><strong>'+esc(x.name)+'</strong><br><span class="muted">'+esc(x.mode)+' · '+new Date(x.created_at).toLocaleString("pt-BR")+'</span> <button class="btn" data-delete-project="'+esc(x.id)+'" type="button">Excluir</button></div>').join(""):'<p class="muted">Nenhum projeto salvo ainda.</p>';
      $("assets").querySelectorAll("[data-download]").forEach(b=>b.onclick=async()=>{try{const res=await fetch(apiBase()+"/api/assets/"+encodeURIComponent(b.dataset.download)+"/download",{credentials:"include"});if(!res.ok)throw new Error("Não foi possível baixar o arquivo.");const blob=await res.blob();const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download="material";a.click();URL.revokeObjectURL(url);}catch(e){status("workspaceStatus",e.message,true);}});
      $("assets").querySelectorAll("[data-delete]").forEach(b=>b.onclick=async()=>{if(!confirm("Excluir este material do servidor?"))return;try{await api("/api/assets/"+encodeURIComponent(b.dataset.delete),{method:"DELETE"});await refresh();}catch(e){status("workspaceStatus",e.message,true);}});
      $("projects").querySelectorAll("[data-delete-project]").forEach(b=>b.onclick=async()=>{if(!confirm("Excluir este projeto?"))return;try{await api("/api/projects/"+encodeURIComponent(b.dataset.deleteProject),{method:"DELETE"});await refresh();}catch(e){status("projectStatus",e.message,true);}});
      status("workspaceStatus",a.items.length+" material(is) · "+p.items.length+" projeto(s) no servidor.");
    }catch(e){status("workspaceStatus",e.message,true);}
  }
  $("loginForm").addEventListener("submit",async e=>{
    e.preventDefault();const btn=e.submitter;btn.disabled=true;status("loginStatus","Verificando acesso…");
    try{const d=await api("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:$("email").value.trim(),password:$("password").value})});csrfToken=d.csrfToken;$("password").value="";showWorkspace();}
    catch(err){status("loginStatus",err.message,true);}finally{btn.disabled=false;}
  });
  $("uploadForm").addEventListener("submit",async e=>{
    e.preventDefault();const files=Array.from($("files").files);if(!files.length)return;const btn=e.submitter;btn.disabled=true;
    try{if(files.length>10)throw new Error("Envie no máximo 10 arquivos por vez.");const form=new FormData();files.forEach(f=>form.append("files",f,f.name));status("uploadStatus","Enviando arquivos ao servidor…");const d=await api("/api/assets",{method:"POST",body:form});status("uploadStatus",d.items.length+" arquivo(s) enviado(s).");$("uploadForm").reset();await refresh();}
    catch(err){status("uploadStatus",err.message,true);}finally{btn.disabled=false;}
  });
  $("projectForm").addEventListener("submit",async e=>{
    e.preventDefault();const btn=e.submitter;btn.disabled=true;
    try{await api("/api/projects",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:$("projectName").value,mode:$("mode").value})});status("projectStatus","Projeto salvo no servidor.");$("projectForm").reset();await refresh();}
    catch(err){status("projectStatus",err.message,true);}finally{btn.disabled=false;}
  });
  $("refreshBtn").addEventListener("click",refresh);
  $("logoutBtn").addEventListener("click",async()=>{try{await api("/api/logout",{method:"POST"});}catch(e){}csrfToken=null;$("workspace").classList.add("hidden");$("loginPanel").classList.remove("hidden");status("loginStatus","Você saiu da sua área.");});
  async function init(){
    const s=document.createElement("script");s.src="./config.js";s.onload=async()=>{if(!apiBase()){status("loginStatus","A API segura ainda não está conectada. Esta tela não aceita login até que o servidor seja configurado.");return;}try{const d=await api("/api/session");csrfToken=d.csrfToken;if(d.authenticated)showWorkspace();}catch(e){status("loginStatus",e.message,true);}};
    document.head.appendChild(s);
  }
  init();
})();