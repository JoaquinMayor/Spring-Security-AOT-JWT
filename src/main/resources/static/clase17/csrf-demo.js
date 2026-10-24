// CLASE 17 - Demo de CSRF (patrón "double submit": cookie XSRF-TOKEN + header X-XSRF-TOKEN).

const $ = (id) => document.getElementById(id);
const show = (titulo, data) => { $('resultado').textContent = titulo + '\n' + data; };

function leerCookie(nombre) {
    const par = document.cookie.split('; ').find(c => c.startsWith(nombre + '='));
    return par ? decodeURIComponent(par.split('=')[1]) : null;
}

async function mostrarRespuesta(titulo, res) {
    // Si no hay sesión, Spring redirige al formulario de login (HTML) en lugar de responder JSON.
    if (res.redirected && res.url.includes('/login')) {
        show(titulo, '⚠ No hay sesión iniciada. Hacé el Paso 0 (/login) primero.');
        return;
    }
    const body = await res.text();
    show(titulo + '  ->  HTTP ' + res.status, body || '(sin cuerpo)');
}

$('btnToken').addEventListener('click', async () => {
    // Al pedir el token, Spring también escribe la cookie XSRF-TOKEN.
    const res = await fetch('/web/csrf-token');
    await mostrarRespuesta('GET /web/csrf-token', res);
});

$('btnLegitima').addEventListener('click', async () => {
    const token = leerCookie('XSRF-TOKEN');
    if (!token) { show('Falta el token', 'Primero tocá "1. Obtener token CSRF"'); return; }
    const res = await fetch('/web/transferencias', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-XSRF-TOKEN': token },
        body: JSON.stringify({ destino: 'CUENTA-AMIGO', monto: 1500 })
    });
    await mostrarRespuesta('POST /web/transferencias CON token', res);
});

$('btnAtaque').addEventListener('click', async () => {
    const res = await fetch('/web/transferencias', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ destino: 'CUENTA-DEL-ATACANTE', monto: 999999 })
    });
    await mostrarRespuesta('POST /web/transferencias SIN token (ataque) -> se espera 403', res);
});
