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
 * List of jitsi instances
 *
 * You can have a rather longer description of the file as well,
 * if you like, and it can span multiple lines.
 *
 * @package    mod_jitsi
 * @copyright  2025 Sergio Comerón <jitsi@sergiocomeron.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(dirname($_SERVER['SCRIPT_FILENAME'], 3) . '/config.php');
require_once(dirname(__FILE__) . '/lib.php');

$id = required_param('id', PARAM_INT);   // Course ID.

require_once($CFG->dirroot . '/course/format/lib.php');

// Redirigir a la vista general moderna si está disponible (Moodle 5.0+).
if (
    class_exists('core_courseformat\base') &&
    method_exists('format_base', 'redirect_to_course_overview')
) {
    format_base::redirect_to_course_overview($id, 'jitsi');
}

// Si estamos en Moodle <5.0, continuar con la lógica tradicional.

$PAGE->set_url('/mod/jitsi/index.php', ['id' => $id]);

if (! $course = $DB->get_record('course', ['id' => $id])) {
    throw new \moodle_exception('invalidcourseid');
}

require_course_login($course);
$PAGE->set_pagelayout('incourse');

$params = [
    'context' => context_course::instance($id),
];
$event = \mod_jitsi\event\course_module_instance_list_viewed::create($params);
$event->add_record_snapshot('course', $course);
$event->trigger();

$strjitsis = get_string('modulenameplural', 'jitsi');
$strjitsi  = get_string('modulename', 'jitsi');

$PAGE->navbar->add($strjitsis);
$PAGE->set_title($strjitsis);
$PAGE->set_heading($course->fullname);
echo $OUTPUT->header();
echo $OUTPUT->heading($strjitsis, 2);

if (! $jitsis = get_all_instances_in_course('jitsi', $course)) {
    notice(get_string('thereareno', 'moodle', $strjitsis), "../../course/view.php?id=$course->id");
    die();
}

$usesections = course_format_uses_sections($course->format);

$timenow  = time();
$strname  = get_string('name');

$table = new html_table();

if ($usesections) {
    $strsectionname = get_string('sectionname', 'format_' . $course->format);
    $table->head  = [$strsectionname, $strname];
    $table->align = ['center', 'left'];
} else {
    $table->head  = [$strname];
    $table->align = ['left'];
}

$currentsection = '';
foreach ($jitsis as $jitsi) {
    $link = $jitsi->visible
        ? "<a href=\"view.php?id=$jitsi->coursemodule\">" . format_string($jitsi->name, true) . "</a>"
        : "<a class=\"dimmed\" href=\"view.php?id=$jitsi->coursemodule\">" . format_string($jitsi->name, true) . "</a>";

    $printsection = '';
    if ($jitsi->section !== $currentsection) {
        if ($jitsi->section) {
            $printsection = get_section_name($course, $jitsi->section);
        }
        if ($currentsection !== '') {
            $table->data[] = 'hr';
        }
        $currentsection = $jitsi->section;
    }

    if ($usesections) {
        $table->data[] = [$printsection, $link];
    } else {
        $table->data[] = [$link];
    }
}

echo '<br />';
echo html_writer::table($table);
echo $OUTPUT->footer();
