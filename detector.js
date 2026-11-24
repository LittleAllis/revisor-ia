/*
 * Motor de detección y enmascaramiento de información sensible (prototipo académico).
 * Funciona 100 % en el navegador (o en Node para pruebas): no envía texto a ningún servicio.
 * Detecta CANDIDATOS: un patrón con formato válido no prueba por sí solo que el dato sea real.
 */
(function (root) {
  'use strict';

  const RIESGO = { CREDENCIAL: 3, DOCUMENTO: 3, TARJETA: 3, CUENTA: 3, LLAVE_PRIVADA: 3, CELULAR: 2, CORREO: 2, IP: 1 };
  const ETIQUETA = { CORREO: '[CORREO]', CELULAR: '[CELULAR]', DOCUMENTO: '[DOCUMENTO]', IP: '[IP]', CREDENCIAL: '[CREDENCIAL]', TARJETA: '[TARJETA]', CUENTA: '[CUENTA]', LLAVE_PRIVADA: '[LLAVE_PRIVADA]' };
  const NIVELES = ['Ninguno', 'Bajo', 'Medio', 'Alto'];
  const CATEGORIAS = Object.keys(RIESGO);

  // Dígito de verificación del NIT colombiano (algoritmo DIAN, módulo 11)
  function digitoNIT(base) {
    const w = [3, 7, 13, 17, 19, 23, 29, 37, 41, 43, 47, 53, 59, 67, 71];
    let s = 0;
    [...base].reverse().forEach((d, i) => { s += +d * w[i]; });
    const r = s % 11;
    return r > 1 ? 11 - r : r;
  }

  // Algoritmo de Luhn: valida números de tarjeta (reduce falsos positivos en cadenas de 16 dígitos)
  function luhn(num) {
    let suma = 0, doble = false;
    for (let i = num.length - 1; i >= 0; i--) {
      let d = +num[i];
      if (doble) { d *= 2; if (d > 9) d -= 9; }
      suma += d; doble = !doble;
    }
    return suma % 10 === 0;
  }

  // Por qué se marca cada categoría (se muestra al usuario)
  const MOTIVO = {
    CORREO: 'Identifica a una persona u organización y permite contactarla o suplantarla.',
    CELULAR: 'Permite contactar o localizar a una persona; es dato personal.',
    DOCUMENTO: 'Identifica de forma única a una persona o empresa; riesgo de suplantación.',
    IP: 'Revela infraestructura interna o expuesta que puede ser objetivo de ataques.',
    CREDENCIAL: 'Da acceso directo a sistemas o servicios; es lo más crítico de proteger.',
    TARJETA: 'Número de tarjeta con formato válido (Luhn); riesgo de fraude financiero.',
    CUENTA: 'Permite recibir o rastrear movimientos de dinero; es dato financiero.',
    LLAVE_PRIVADA: 'Permite descifrar información o suplantar un servidor o usuario; nunca debe compartirse.',
  };

  // Ventanas de contexto (texto sin tildes y en minúsculas)
  const sinTildes = (s) => s.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
  const antes = (t, i, n) => sinTildes(t.slice(Math.max(0, i - n), i));
  const despues = (t, i, n) => sinTildes(t.slice(i, i + n));

  const CTX_DOC = /(?:\bc\.?\s?c\.?|cedula|documento|identificacion|\bnit\b|\bdni\b|\bid\b|tarjeta de identidad)[^\d]{0,25}$/;
  const CTX_DINERO = /(?:\$|valor|total|precio|pagar|pago|costo|monto|presupuesto|salario)[^\d]{0,15}$/;
  const POST_DINERO = /^\s*(?:pesos|cop|usd|dolares|mil\b|millones)/;
  const CTX_TARJETA = /(?:tarjeta|visa|mastercard|master card|amex|credito|debito|card)[^\d]{0,40}$/;
  const CTX_CUENTA = /(?:cuenta\s+(?:de\s+)?(?:ahorros?|corriente|bancaria|nequi|daviplata)|cuenta\s*(?:numero|no\.?|nro\.?|#)|\bnequi|daviplata|\biban)[^\d]{0,30}$/;
  const CTX_VERSION = /\b(?:version|ver|v|build|release)\s?[^\d\w]{0,2}$/;

  // El orden importa: si dos reglas coinciden en el mismo fragmento gana la primera.
  const REGLAS = [
    { cat: 'LLAVE_PRIVADA', // bloque PEM completo (o desde el encabezado si está cortado)
      re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g },
    { cat: 'CREDENCIAL', // palabra clave + valor: api_key=..., password: ..., "mi contraseña es ..."
      re: /\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?token|token(?:\s+de\s+acceso)?|passw(?:or)?d|pwd|contrase[ñn]a|clave)\s*(?:[:=]|\bes\b)\s*["']?([^\s"',;]{3,}[^\s"',;.])/gi,
      ok: (m) => /[:=]/.test(m[0]) || /\d/.test(m[1]) }, // con "es" se exige algún dígito (evita "la clave es importante")
    { cat: 'CREDENCIAL', // formatos conocidos de llaves y tokens
      re: /\b(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,})|Bearer\s+[A-Za-z0-9._~+\/-]{20,}=*/g },
    { cat: 'TARJETA', // 13–19 dígitos agrupados de 4 (o formato Amex) y que pasen Luhn
      re: /(?<![\d.-])(?:\d{4}[ -]?){3}\d{4}(?![\d-])|(?<![\d.-])3[47]\d{2}[ -]?\d{6}[ -]?\d{5}(?![\d-])/g,
      ok: (m) => luhn(m[0].replace(/\D/g, '')) },
    { cat: 'TARJETA', // 13–19 dígitos con contexto de tarjeta, aunque falle Luhn (puede ser un error de digitación)
      re: /(?<![\d.-])\d(?:[ -]?\d){12,18}(?![\d-])/g,
      ok: (m, t) => CTX_TARJETA.test(antes(t, m.index, 50)) },
    { cat: 'TARJETA', // código de seguridad: "cvv es 123", "CVC: 456"
      re: /\b(?:cvv2?|cvc2?|c[oó]digo\s+de\s+seguridad)\s*(?:[:=]|\bes\b)?\s*\d{3,4}(?!\d)/gi },
    { cat: 'TARJETA', // fecha de expiración: "expiración es 05/31", "vence: 12-2029"
      re: /\b(?:expiraci[oó]n|expira|vencimiento|vence|exp\.?)\s*(?:es|el|:|=)?\s*(?:0[1-9]|1[0-2])\s*[\/-]\s*(?:\d{4}|\d{2})(?!\d)/gi },
    { cat: 'CORREO', // correo con dato ofuscado: ana [arroba] empresa.test, ana(at)empresa.test
      re: /[A-Za-z0-9._%+-]+\s*(?:[\[(]\s*(?:arroba|at)\s*[\])]|\s+arroba\s+)\s*[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/gi },
    { cat: 'CORREO',
      re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g },
    { cat: 'DOCUMENTO', // NIT con dígito de verificación válido
      re: /(?<![\d.])(\d{1,3}(?:\.?\d{3}){2,3})-(\d)(?!\d)/g,
      ok: (m) => digitoNIT(m[1].replace(/\./g, '')) === +m[2] },
    { cat: 'IP', // IPv4 con octetos 0–255; se descartan números de versión
      re: /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d|\.\d)/g,
      ok: (m, t) => !CTX_VERSION.test(antes(t, m.index, 12)) },
    { cat: 'CELULAR', // móvil colombiano: 3XX XXX XXXX, con o sin +57
      re: /(?<!\d)(?:\+?57[\s-]?)?3\d{2}[\s.-]?\d{3}(?:[\s.-]?\d{4}|[\s.-]\d{2}[\s.-]\d{2})(?!\d)/g,
      ok: (m, t) => !CTX_DOC.test(antes(t, m.index, 35)) }, // "cédula 3012345678" es documento, no celular
    { cat: 'CUENTA', // 8–16 dígitos (o con guiones) solo si hay contexto bancario explícito
      re: /(?<![\d.,-])(?:\d{3,6}(?:-\d{2,8}){1,3}|\d{8,16})(?!\d)/g,
      ok: (m, t) => { const n = m[0].replace(/\D/g, '').length; return n >= 8 && n <= 16 && CTX_CUENTA.test(antes(t, m.index, 45)); } },
    { cat: 'DOCUMENTO', // cédula con puntos (1.234.567.890); se descartan montos de dinero
      re: /(?<![\d.])\d{1,3}(?:\.\d{3}){2,3}(?!\d|\.\d)/g,
      ok: (m, t) => !CTX_DINERO.test(antes(t, m.index, 25)) && !POST_DINERO.test(despues(t, m.index + m[0].length, 12)) },
    { cat: 'DOCUMENTO', // 6–10 dígitos seguidos: solo si hay contexto (cédula, CC, documento, NIT...)
      re: /(?<![\d.,-])\d{6,10}(?!\d|[.,]\d)/g,
      ok: (m, t) => CTX_DOC.test(antes(t, m.index, 35)) },
  ];

  function analizar(texto) {
    const aceptados = [];
    for (const r of REGLAS) {
      r.re.lastIndex = 0;
      let m;
      while ((m = r.re.exec(texto)) !== null) {
        if (m[0].length === 0) { r.re.lastIndex++; continue; }
        const inicio = m.index, fin = inicio + m[0].length;
        if (r.ok && !r.ok(m, texto)) continue;
        if (aceptados.some((a) => inicio < a.fin && fin > a.inicio)) continue; // solapamiento
        aceptados.push({ cat: r.cat, inicio, fin, texto: m[0], riesgo: RIESGO[r.cat], etiqueta: ETIQUETA[r.cat] });
      }
    }
    aceptados.sort((a, b) => a.inicio - b.inicio);
    const max = aceptados.reduce((x, h) => Math.max(x, h.riesgo), 0);
    return { hallazgos: aceptados, nivel: NIVELES[max] };
  }

  // Reemplaza solo los hallazgos recibidos (el usuario decide cuáles aceptar).
  // Con numerar=true usa [CORREO_1], [CORREO_2]... y devuelve el mapa para restaurar la respuesta de la IA.
  function enmascararReversible(texto, hallazgos, numerar) {
    const mapa = {}, cont = {}, etq = new Map();
    const orden = [...hallazgos].sort((a, b) => a.inicio - b.inicio);
    const etiquetaDe = (h) => {
      if (!numerar) return h.etiqueta;
      const k = h.cat + '|' + h.texto; // mismo dato -> misma etiqueta
      if (!etq.has(k)) {
        cont[h.cat] = (cont[h.cat] || 0) + 1;
        const e = `[${h.cat}_${cont[h.cat]}]`;
        etq.set(k, e); mapa[e] = h.texto;
      }
      return etq.get(k);
    };
    const nuevas = new Map(orden.map((h) => [h, etiquetaDe(h)]));
    const out = [...orden].reverse().reduce((t, h) => t.slice(0, h.inicio) + nuevas.get(h) + t.slice(h.fin), texto);
    return { texto: out, mapa };
  }
  const enmascarar = (texto, hallazgos) => enmascararReversible(texto, hallazgos, false).texto;
  const restaurar = (texto, mapa) => Object.keys(mapa).reduce((t, k) => t.split(k).join(mapa[k]), texto);

  // ---- Evaluación contra un banco etiquetado: [tipo, texto, [[categoria, valor], ...]] ----
  const ahora = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());
  const coincide = (h, e) => h.cat === e[0] && (h.texto.includes(e[1]) || e[1].includes(h.texto));
  const razon = (a, b) => (b === 0 ? null : a / b);

  function evaluar(banco) {
    const tot = { vp: 0, fp: 0, fn: 0 }, porCat = {}, detalle = [];
    CATEGORIAS.forEach((c) => { porCat[c] = { vp: 0, fp: 0, fn: 0 }; });
    let fpTextos = 0, vnTextos = 0, ms = 0;

    banco.forEach(([tipo, texto, esperado], idx) => {
      const t0 = ahora();
      const det = analizar(texto).hallazgos;
      ms += ahora() - t0;

      const usados = new Set(), faltan = [];
      esperado.forEach((e) => {
        const k = det.findIndex((h, j) => !usados.has(j) && coincide(h, e));
        if (k >= 0) { usados.add(k); tot.vp++; porCat[e[0]].vp++; } else { faltan.push(e); tot.fn++; porCat[e[0]].fn++; }
      });
      const sobran = det.filter((_, j) => !usados.has(j));
      sobran.forEach((h) => { tot.fp++; porCat[h.cat].fp++; });

      if (esperado.length === 0) { sobran.length ? fpTextos++ : vnTextos++; }
      detalle.push({
        id: idx + 1, tipo, texto,
        esperado: esperado.map((e) => `${e[0]}:${e[1]}`).join(' | '),
        detectado: det.map((h) => `${h.cat}:${h.texto}`).join(' | '),
        vp: esperado.length - faltan.length, fp: sobran.length, fn: faltan.length,
      });
    });

    const porTipo = {};
    detalle.forEach((d) => {
      const k = porTipo[d.tipo] || (porTipo[d.tipo] = { textos: 0, vp: 0, fp: 0, fn: 0 });
      k.textos++; k.vp += d.vp; k.fp += d.fp; k.fn += d.fn;
    });
    const exh = razon(tot.vp, tot.vp + tot.fn);
    return {
      textos: banco.length, ...tot, fpTextos, vnTextos,
      precision: razon(tot.vp, tot.vp + tot.fp),
      exhaustividad: exh,
      tasaFP: razon(fpTextos, fpTextos + vnTextos), // sobre textos SIN datos sensibles
      tiempoMs: ms / banco.length,
      cumpleMeta: exh !== null && exh >= 0.85,
      porCat, porTipo, detalle,
    };
  }

  const api = { analizar, enmascarar, enmascararReversible, restaurar, evaluar, digitoNIT, luhn, MOTIVO, CATEGORIAS, NIVELES };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.Detector = api;
})(typeof self !== 'undefined' ? self : this);
