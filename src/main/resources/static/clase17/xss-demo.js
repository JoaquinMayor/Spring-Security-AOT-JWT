// CLASE 17 - Demo de XSS.
// Este JavaScript está en un archivo aparte (no "inline" en el HTML) porque la Content-Security-Policy
// "script-src 'self'" solo permite scripts que vengan de archivos de nuestro propio dominio.

let jwt = null;

const $ = (id) => document.getElementById(id);

$('btnLogin').addEventListener('click', async () => {
    const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: $('username').value, password: $('password').value })
    });
    if (res.ok) {
        jwt = (await res.json()).token;
        $('loginStatus').textContent = '✅ Token obtenido';
    } else {
        $('loginStatus').textContent = '❌ Login fallido (' + res.status + ')';
    }
});

$('btnPublicar').addEventListener('click', async () => {
    if (!jwt) { $('publicarStatus').textContent = 'Primero hacé login'; return; }
    const res = await fetch('/api/clase17/comentarios', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + jwt },
        body: JSON.stringify({ texto: $('texto').value })
    });
    $('publicarStatus').textContent = res.ok ? '✅ Publicado' : '❌ Error ' + res.status;
});

$('btnCargar').addEventListener('click', async () => {
    // ❌ VULNERABLE: la API devuelve el texto tal cual y lo pintamos con innerHTML.
    //    El navegador interpreta las etiquetas HTML y ejecuta el onerror=...
    const crudos = await (await fetch('/api/clase17/comentarios/sin-escapar')).json();
    $('vulnerable').innerHTML = crudos
        .map(c => '<div class="comment"><b>' + c.autor + ':</b> ' + c.texto + '</div>')
        .join('');

    // ✅ SEGURO: textContent nunca interpreta HTML, solo muestra texto.
    //    (Además, este endpoint ya devuelve la salida escapada: &lt;img ...&gt;)
    const escapados = await (await fetch('/api/clase17/comentarios')).json();
    const seguro = $('seguro');
    seguro.replaceChildren();
    crudos.forEach(c => {
        const div = document.createElement('div');
        div.className = 'comment';
        div.textContent = c.autor + ': ' + c.texto;
        seguro.appendChild(div);
    });
    if (escapados.length > 0) {
        const pre = document.createElement('pre');
        pre.textContent = 'JSON escapado que devuelve GET /api/clase17/comentarios:\n'
            + JSON.stringify(escapados[0], null, 2);
        seguro.appendChild(pre);
    }
});
