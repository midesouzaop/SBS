/* Integração preparada para o backend remoto. Requer API hospedada e URL configurada em config.js. */
(() => {
  const $ = id => document.getElementById(id);
  let csrfToken = null;
  const apiBase = () => String(window.DO_ZERO_SA_API_URL || "").trim().replace(/\/+$/, "");
  const esc = s => String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const sizeText = n => n < 1048576 ? Math.round(n/1024)+" KB" : (n/1048576).toFixed(1)+" MB";
  async function api(path, options={}) {
    const base = apiBase();
    if (!base) throw new Error("A API ainda não foi hospedada/configurada.");
    const headers = new Headers(options.headers || {});
    if (csrfToken && options.method && options.method !== "GET") headers.set("X-CSRF-Token", csrfToken);
    const response = await fetch(base + path, {...options, headers, credentials:"include"});
    const data = await response.json().catch(()=>({}));
    if (!response.ok) throw new Error(data.error || ("Falha na API ("+response.status+")."));
    return data;
  }
  function status(message, error=false) {
    const el=$("remoteStatus");
    if (el) { el.textContent=message; el.style.color=error ? "#ffb3a8" : "#a2adbd"; }
  }
  function mount() {
    const parent=$("localLibrary");
    if (!parent || $("remoteLibrary")) return;
    const panel=document.createElement("section");
    panel.id="remoteLibrary";
    panel.style.cssText="margin-top:20px;padding:18px;border:1px solid #3b465b;border-radius:14px;background:#0d121b";
    panel.innerHTML='<div class="eyebrow">Próxima camada • servidor</div><h3 style="margin:8px 0">Biblioteca da plataforma</h3><p style="font-size:12px;color:#a2adbd;margin:0 0 14px">Quando a API estiver hospedada, conecte a conta administrativa para enviar os materiais ao servidor e acessá-los em outros dispositivos.</p><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:9px"><label style="font-size:12px;color:#a2adbd">Usuário administrativo<input id="remoteUser" autocomplete="username" style="display:block;width:100%;margin-top:5px;background:#101722;border:1px solid #39445a;border-radius:9px;padding:10px;color:white" placeholder="Usuário"></label><label style="font-size:12px;color:#a2adbd">Senha<input id="remotePass" type="password" autocomplete="current-password" style="display:block;width:100%;margin-top:5px;background:#101722;border:1px solid #39445a;border-radius:9px;padding:10px;color:white" placeholder="Senha"></label></div><div class="actions"><button type="button" class="primary" id="remoteLogin">Conectar servidor</button><button type="button" class="pill" id="remoteUpload" disabled>Enviar materiais salvos</button><button type="button" class="pill" id="remoteRefresh" disabled>Atualizar biblioteca</button></div><p id="remoteStatus" role="status" style="font-size:12px;margin:12px 0 0;color:#a2adbd"></p><div id="remoteFiles" class="file-list"></div>';
    parent.appendChild(panel);
    $("remoteLogin").addEventListener("click", login);
    $("remoteUpload").addEventListener("click", uploadLocalFiles);
    $("remoteRefresh").addEventListener("click", refreshRemote);
    if (!apiBase()) status("A API está preparada no repositório, mas ainda precisa ser hospedada. Nenhum arquivo será enviado até isso estar configurado.");
    else {
      status("Endereço da API configurado. Verificando sessão…");
      api("/api/session").then(data=>{
        csrfToken=data.csrfToken || null;
        setConnected(data.authenticated);
        status(data.authenticated ? "Conectado como "+data.username+"." : "Servidor localizado. Entre com a conta administrativa.");
        if (data.authenticated) refreshRemote();
      }).catch(err=>status(err.message,true));
    }
  }
  function setConnected(connected) {
    if ($("remoteUpload")) $("remoteUpload").disabled=!connected;
    if ($("remoteRefresh")) $("remoteRefresh").disabled=!connected;
  }
  async function login() {
    const user=$("remoteUser").value.trim(), password=$("remotePass").value;
    if (!apiBase()) return status("A API ainda não foi hospedada/configurada.",true);
    if (!user || !password) return status("Preencha usuário e senha administrativos.",true);
    $("remoteLogin").disabled=true;
    try {
      const data=await api("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:user,password})});
      csrfToken=data.csrfToken;
      $("remotePass").value="";
      setConnected(true);
      status("Conectado com segurança. Carregando biblioteca…");
      await refreshRemote();
    } catch(err) {
      setConnected(false);
      status(err.message,true);
    } finally { $("remoteLogin").disabled=false; }
  }
  async function refreshRemote() {
    try {
      const data=await api("/api/assets");
      const box=$("remoteFiles");
      box.innerHTML=data.items.length ? "" : '<p style="font-size:12px;color:#a2adbd">Nenhum material no servidor ainda.</p>';
      data.items.forEach(item=>{
        const row=document.createElement("div");
        row.className="file-row";
        row.innerHTML='<span style="min-width:0;overflow-wrap:anywhere"><strong>'+esc(item.original_name)+'</strong><br><small style="color:#a2adbd">'+sizeText(item.size_bytes)+' · '+new Date(item.created_at).toLocaleString("pt-BR")+'</small></span><span class="tag">Servidor</span>';
        box.appendChild(row);
      });
      status(data.items.length+" material(is) na biblioteca do servidor.");
    } catch(err) { status(err.message,true); }
  }
  function getLocalAssets() {
    return new Promise((resolve,reject)=>{
      const req=indexedDB.open("do-zero-sa",1);
      req.onerror=()=>reject(req.error);
      req.onsuccess=()=>{
        const db=req.result;
        if (!db.objectStoreNames.contains("assets")) { db.close(); return resolve([]); }
        const q=db.transaction("assets","readonly").objectStore("assets").getAll();
        q.onsuccess=()=>{resolve(q.result || []);db.close();};
        q.onerror=()=>{reject(q.error);db.close();};
      };
    });
  }
  async function uploadLocalFiles() {
    const button=$("remoteUpload");
    button.disabled=true;
    try {
      const assets=await getLocalAssets();
      if (!assets.length) { status("Não há arquivos salvos localmente para enviar.",true); return; }
      let uploaded=0;
      for (const asset of assets) {
        const form=new FormData();
        form.append("files",asset.blob,asset.name);
        status("Enviando "+(uploaded+1)+" de "+assets.length+": "+asset.name+"…");
        await api("/api/assets",{method:"POST",body:form});
        uploaded++;
      }
      status(uploaded+" arquivo(s) enviado(s) ao servidor.");
      await refreshRemote();
    } catch(err) {
      status(err.message,true);
    } finally { button.disabled=!csrfToken; }
  }
  function init() {
    mount();
    if (!$("remoteLibrary") && "MutationObserver" in window) {
      const observer = new MutationObserver(() => {
        if ($("localLibrary")) { observer.disconnect(); mount(); }
      });
      observer.observe(document.body, {childList:true, subtree:true});
    }
  }
  if (document.readyState==="loading") document.addEventListener("DOMContentLoaded",init,{once:true});
  else init();
})();