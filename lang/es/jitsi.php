<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Spanish strings for jitsi (session minutes MVP).
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['actaactionitems'] = 'Pendientes';
$string['actaactionitemsnone'] = 'No se identificaron pendientes.';
$string['actaapiendpoint'] = 'Endpoint de la API LLM';
$string['actaapiendpointex'] = 'URL base compatible con OpenAI (por ejemplo https://api.openai.com/v1). Se añade /chat/completions si falta. Solo se usa para el acta de la sesión.';
$string['actaapikey'] = 'Clave API LLM (BYOK)';
$string['actaapikeyactivity'] = 'Clave API del acta (opcional)';
$string['actaapikeyactivity_help'] = 'Clave API compatible con OpenAI, opcional, solo para esta actividad. Se usa solo si el sitio no tiene Vertex AI ya configurado. Si se indica, se usa en lugar de la clave del sitio. Déjela vacía para conservar la clave guardada o heredar la del sitio.';
$string['actaapikeyex'] = 'Se usa cuando el sitio no tiene Vertex AI ya configurado. Su propia clave API compatible con OpenAI. El plugin no usa ninguna clave de pago del desarrollador. Si Vertex está configurado, se usa Vertex; esta clave queda como reserva. La clave nunca se escribe en los registros.';
$string['actaapimodel'] = 'Modelo LLM';
$string['actaapimodelex'] = 'Nombre del modelo enviado a la API compatible con OpenAI (por defecto gpt-4o-mini).';
$string['actaattendance'] = 'Asistencia';
$string['actaempty'] = 'Aún no hay actas. Se generan cuando un profesor cuelga, o puede generarlas desde la última ventana de asistencia.';
$string['actaenabled'] = 'Activar acta de la sesión';
$string['actaenabledex'] = 'Si está activado, al colgar se encola un acta: resumen breve, asistencia de los registros de participación existentes y pendientes. Usa la configuración Vertex AI del sitio si ya existe; si no, la clave compatible con OpenAI de abajo (sitio o actividad). Si no hay ninguna, la reunión funciona igual y no se genera acta. No se suben grabaciones; si ya hay transcripción, se usa esa.';
$string['actaerror'] = 'No se pudo generar el acta. La asistencia se guarda cuando está disponible.';
$string['actagenerate'] = 'Generar acta de la última sesión';
$string['actagenerating'] = 'Se está generando el acta…';
$string['actaheading'] = 'Acta de la sesión';
$string['actaheadingex'] = 'Acta al colgar. Si Vertex AI ya está configurado en el sitio, se usa automáticamente; si no, la clave BYOK de abajo. Sin selector de proveedor, facturación ni marketplace.';
$string['actallmempty'] = 'El LLM devolvió una respuesta vacía.';
$string['actallmhttp'] = 'El LLM devolvió HTTP {$a}.';
$string['actallmjson'] = 'La respuesta del LLM no era JSON válido.';
$string['actallmtransport'] = 'No se pudo contactar con el endpoint del LLM.';
$string['actanotavailable'] = 'El acta está desactivado porque no hay Vertex AI ni una clave BYOK disponibles.';
$string['actaprivacynote'] = 'El acta usa los registros de asistencia existentes. Si ya hay una transcripción, se envía a Vertex AI cuando está configurado, o si no a su LLM BYOK; las grabaciones no se suben.';
$string['actaqueued'] = 'El acta se ha encolado. Aparecerá aquí en breve.';
$string['actashow'] = 'Mostrar el acta en esta actividad';
$string['actashow_help'] = 'Si está activado, quienes puedan ver el acta lo verán en esta actividad. Desmárquelo para ocultarlo aquí (también a los profesores). El acta se puede seguir generando cuando un profesor cuelga; aparecerá al volver a marcar esta casilla.';
$string['actasource_metadata'] = 'Generada solo a partir de la asistencia (sin transcripción)';
$string['actasource_transcript'] = 'Generada a partir de la transcripción de la sesión';
$string['actasummary'] = 'Resumen';
$string['actasummaryunavailable'] = 'No había contenido de la sesión que se pudiera resumir.';
$string['actatitle'] = 'Acta de la sesión';
$string['jitsi:viewacta'] = 'Ver el acta de la sesión';
$string['privacy:metadata:actallm'] = 'Cuando el acta está activada y Vertex AI no está configurado, se envían la transcripción (si ya existe) y los nombres de asistencia al endpoint BYOK compatible con OpenAI. No se suben grabaciones. La clave la aporta el sitio o la actividad; no se usa ninguna clave de pago del proveedor.';
$string['privacy:metadata:vertexai'] = 'Cuando un profesor genera un resumen, cuestionario o transcripción IA, la grabación se envía a Google Vertex AI (Gemini). Cuando el acta está activada y Vertex AI ya está configurado, también se envían la transcripción existente (si hay) y los nombres de asistencia; las grabaciones no se suben para el acta. La región se configura en los ajustes del plugin.';
$string['privacy:metadata:vertexai:attendance'] = 'Nombres visibles y minutos conectados de los asistentes, enviados cuando el acta usa la configuración Vertex AI existente.';
$string['privacy:metadata:vertexai:recording'] = 'La grabación de vídeo se envía a Google Vertex AI para generar contenido educativo (resumen, cuestionario, transcripción). El procesamiento ocurre en la región Vertex AI configurada.';
$string['privacy:metadata:vertexai:transcript'] = 'Texto de transcripción ya almacenado, enviado a Vertex AI cuando el acta usa esa configuración. Las grabaciones no se suben para el acta.';
$string['privacy:metadata:actallm:attendance'] = 'Nombres visibles y minutos conectados de los asistentes, para listar quién estuvo presente.';
$string['privacy:metadata:actallm:transcript'] = 'Texto de transcripción ya almacenado para la misma ventana de sesión.';
$string['privacy:metadata:jitsi_session_acta'] = 'Actas generadas al terminar una clase, con la asistencia copiada de los registros de participación, el resumen breve y los pendientes.';
$string['privacy:metadata:jitsi_session_acta:actionitems'] = 'Lista JSON de pendientes extraídos de la sesión.';
$string['privacy:metadata:jitsi_session_acta:attendancejson'] = 'Lista JSON de asistentes (id de usuario, nombre y minutos conectados) de la sesión.';
$string['privacy:metadata:jitsi_session_acta:summary'] = 'Resumen breve de la sesión generado por IA.';
$string['privacy:metadata:jitsi_session_acta:userid'] = 'Identificador del profesor que terminó la sesión y disparó el acta.';
$string['task_generate_session_acta'] = 'Generar acta de la sesión';
