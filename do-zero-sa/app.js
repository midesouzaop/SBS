/* Do Zero a S.A. — biblioteca local e projetos persistidos no dispositivo.
   Esta camada é uma etapa funcional local; não substitui o armazenamento remoto autenticado. */
(() => {
  const DB_NAME = "do-zero-sa";
  const DB_VERSION = 1;
  let db;
  const $ = (id) => document.getElementById(id);
  const bytes = (n) => n < 1024*1024 ? (n/1024).toFixed(0)+" KB" : (n/1024/1024).toFixed(1)+" MB";
  const esc = (s) => String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  function openDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const d = req.result;
        if (!d.objectStoreNames.contains("assets")) d.createObjectStore("assets", {keyPath:"id"});
        if (!d.objectStoreNames.contains("projects")) d.createObjectStore("projects", {keyPath:"id"});
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  function all(store) {
    return new Promise((resolve, reject) => {
      const req = db.transaction(store, "readonly").objectStore(store).getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });
  }
  function put(store, value) {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(store, "readwrite");
      tx.objectStore(store).put(value);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error || new Error("Operação cancelada"));
    });
  }
  function remove(store, id) {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(store, "readwrite");
      tx.objectStore(store).delete(id);
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  }
  function typeOf(file) {
    if (/\.(ppt|pptx)$/i.test(file.name)) return "Apresentação";
    if (/\.pdf$/i.test(file.name)) return "PDF";
    if (file.type.startsWith("video/")) return "Vídeo";
    if (/\.(doc|docx)$/i.test(file.name)) return "Documento";
    return "Arquivo";
  }
  function addPanel() {
    const zone = $("dropzone");
    if (!zone || $("localLibrary")) return;
    const panel = document.createElement("div");
    panel.id = "localLibrary";
    panel.style.cssText = "margin-top:20px;text-align:left";
    panel.innerHTML = '<div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap"><strong style="font-size:14px">Minha biblioteca neste dispositivo</strong><button type="button" class="close" id="clearLocal">Apagar biblioteca local</button></div><p style="font-size:12px;color:#a2adbd;margin:5px 0 12px">Meus arquivos ficam armazenados neste navegador e não são enviados à nuvem. Não limpe os dados do navegador enquanto precisar deles.</p><div id="savedFiles" class="file-list"></div><div style="height:1px;background:#293242;margin:22px 0"></div><strong style="font-size:14px">Projetos preparados</strong><div id="savedProjects" class="file-list"></div>';
    zone.appendChild(panel);
    $("clearLocal").addEventListener("click", async () => {
      if (!confirm("Apagar meus arquivos e projetos salvos neste dispositivo? Esta ação não pode ser desfeita.")) return;
      await Promise.all([clearStore("assets"), clearStore("projects")]);
      await render();
      if (typeof showToast === "function") showToast("Meus arquivos locais foram apagados.");
    });
  }
  function clearStore(store) {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(store, "readwrite");
      tx.objectStore(store).clear();
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  }
  async function render() {
    const assets = await all("assets");
    const projects = await all("projects");
    const filesEl = $("savedFiles");
    const projectsEl = $("savedProjects");
    if (!filesEl || !projectsEl) return;
    filesEl.innerHTML = assets.length ? "" : '<p style="font-size:12px;color:#a2adbd">Ainda não salvei materiais neste dispositivo.</p>';
    assets.sort((a,b)=>b.addedAt-a.addedAt).forEach(item => {
      const row = document.createElement("div");
      row.className = "file-row";
      row.innerHTML = '<span style="min-width:0;overflow-wrap:anywhere"><strong>'+esc(item.name)+'</strong><br><small style="color:#a2adbd">'+esc(typeOf({name:item.name,type:item.type||""}))+' · '+bytes(item.size)+' · '+new Date(item.addedAt).toLocaleDateString("pt-BR")+'</small></span><button type="button" class="close" data-delete-file="'+esc(item.id)+'">Excluir</button>';
      filesEl.appendChild(row);
    });
    projectsEl.innerHTML = projects.length ? "" : '<p style="font-size:12px;color:#a2adbd">Ainda não preparei projetos neste dispositivo.</p>';
    projects.sort((a,b)=>b.createdAt-a.createdAt).forEach(item => {
      const row = document.createElement("div");
      row.className = "file-row";
      row.innerHTML = '<span style="min-width:0;overflow-wrap:anywhere"><strong>'+esc(item.name)+'</strong><br><small style="color:#a2adbd">'+esc(item.mode)+' · '+new Date(item.createdAt).toLocaleString("pt-BR")+'</small></span><button type="button" class="close" data-delete-project="'+esc(item.id)+'">Excluir</button>';
      projectsEl.appendChild(row);
    });
    filesEl.querySelectorAll("[data-delete-file]").forEach(btn=>btn.addEventListener("click", async()=>{await remove("assets",btn.dataset.deleteFile);await render();}));
    projectsEl.querySelectorAll("[data-delete-project]").forEach(btn=>btn.addEventListener("click", async()=>{await remove("projects",btn.dataset.deleteProject);await render();}));
  }
  async function saveSelectedFiles() {
    const files = Array.from($("files")?.files || []);
    for (const file of files) {
      const id = [file.name,file.size,file.lastModified].join("::");
      await put("assets", {id,name:file.name,size:file.size,type:file.type,addedAt:Date.now(),blob:file});
    }
    await render();
    if (files.length && typeof showToast === "function") showToast(files.length+" arquivo(s) salvo(s) neste dispositivo.");
  }
  async function init() {
    try {
      if (!("indexedDB" in window)) throw new Error("Este navegador não oferece armazenamento local compatível.");
      db = await openDB();
      addPanel();
      $("files")?.addEventListener("change", () => saveSelectedFiles().catch(err => {
        console.error(err);
        if (typeof showToast === "function") showToast("Não foi possível salvar. O navegador pode estar sem espaço disponível.");
      }));
      const oldStartProject = window.startProject;
      window.startProject = async function() {
        const name = $("projectName")?.value.trim() || "Novo projeto";
        const mode = $("creationMode")?.value || "Aula original com capítulos e legendas";
        try {
          await put("projects", {id:crypto.randomUUID ? crypto.randomUUID() : String(Date.now())+"-"+Math.random(),name,mode,createdAt:Date.now()});
          if (typeof oldStartProject === "function") oldStartProject();
          await render();
        } catch (err) {
          console.error(err);
          if (typeof showToast === "function") showToast("Não foi possível salvar o projeto neste dispositivo.");
        }
      };
      await render();
    } catch (err) {
      console.error(err);
      const note = document.querySelector(".notice");
      if (note) note.textContent = "Armazenamento local indisponível neste navegador. A biblioteca na nuvem será conectada na etapa de backend.";
    }
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init, {once:true});
  else init();
})();