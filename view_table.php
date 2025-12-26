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
 * Defines the accept event.
 *
 * @package    mod_jitsi
 * @copyright  2023 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();
require_once($CFG->libdir . '/tablelib.php');
require_once($CFG->libdir . '/adminlib.php');

/**
 * Extend the standard table class for jitsi.
 */
class mod_view_table extends table_sql {
    /**
     * Constructor
     * @param int $uniqueid all tables have to have a unique id, this is used
     *      as a key when storing table properties like sort order in the session.
     */
    public function __construct($uniqueid) {
        parent::__construct($uniqueid);
        // Define the list of columns to show.
        $columns = ['id'];
        $this->define_columns($columns);

        // Define the titles of columns to show in header.
        $headers = ['Video'];
        $this->define_headers($headers);
    }

    /**
     * This function is called for each data row to allow processing of the
     * username value.
     *
     * @param object $values Contains object with all the values of record.
     * @return $string Return username with link to profile or username only
     *     when downloading.
     */
    protected function col_id($values) {
        global $DB, $OUTPUT, $CFG;

        if ($CFG->branch >= 500) {
            $alignmentclass = 'text-end';
            $videocontainerstart = "<div class=\"ratio ratio-16x9\">";
            $iframeclass = "";
        } else {
            $alignmentclass = 'text-right';
            $videocontainerstart = "<div class=\"embed-responsive embed-responsive-16by9\">";
            $iframeclass = "class=\"embed-responsive-item\"";
        }

        $jitsi = $DB->get_record('jitsi', ['id' => $values->jitsi]);
        $module = $DB->get_record('modules', ['name' => 'jitsi']);
        $cm = $DB->get_record('course_modules', ['instance' => $values->jitsi, 'module' => $module->id]);
        $context = context_module::instance($cm->id);

        $record = $DB->get_record('jitsi_record', ['id' => $values->id]);
        $sourcerecord = $DB->get_record('jitsi_source_record', ['id' => $record->source]);
        if ($sourcerecord->id && $sourcerecord->link != null) {
            $deleteurl = new moodle_url('/mod/jitsi/view.php?id=' . $cm->id . '&deletejitsirecordid=' .
            $record->id . '&sesskey=' . sesskey() . '#record');
            $deleteicon = new pix_icon('t/delete', get_string('delete'));
            $deleteaction = $OUTPUT->action_icon(
                $deleteurl,
                $deleteicon,
                new confirm_action(get_string('confirmdeleterecordinactivity', 'jitsi'))
            );

            $hideurl = new moodle_url('/mod/jitsi/view.php?id=' . $cm->id . '&hidejitsirecordid=' .
                $record->id . '&sesskey=' . sesskey() . '#record');
            $showurl = new moodle_url('/mod/jitsi/view.php?id=' . $cm->id . '&showjitsirecordid=' .
                $record->id . '&sesskey=' . sesskey() . '#record');
            $hideicon = new pix_icon('t/hide', get_string('hide'));
            $showicon = new pix_icon('t/show', get_string('show'));
            $hideaction = $OUTPUT->action_icon($hideurl, $hideicon, new confirm_action('Hide?'));
            $showaction = $OUTPUT->action_icon($showurl, $showicon, new confirm_action('Show?'));

            $tmpl = new \core\output\inplace_editable(
                'mod_jitsi',
                'recordname',
                $values->id,
                has_capability('mod/jitsi:editrecordname', $context),
                format_string($values->name),
                $values->name,
                get_string('editrecordname', 'jitsi'),
                get_string('newvaluefor', 'jitsi') . format_string($values->name)
            );
            if ($jitsi->sessionwithtoken == 0) {
                if (has_capability('mod/jitsi:deleterecord', $context) && !has_capability('mod/jitsi:hide', $context)) {
                    return "<h5>" . $OUTPUT->render($tmpl) . "</h5><h6 class=\"card-subtitle mb-2 text-muted\">" .
                        userdate($values->timecreated) . "</h6><span class=\"align-middle " .
                        $alignmentclass . "\"><p>" . $deleteaction .
                        "</p></span>" . $videocontainerstart .
                        "<iframe " . $iframeclass . " src=\"https://youtube.com/embed/" . $values->link . "\"
                        allowfullscreen></iframe></div><br>";
                }
                if (has_capability('mod/jitsi:hide', $context) && !has_capability('mod/jitsi:deleterecord', $context)) {
                    if ($record->visible != 0) {
                        return "<h5>" . $OUTPUT->render($tmpl) . "</h5><h6 class=\"card-subtitle mb-2 text-muted\">" .
                            userdate($values->timecreated) . "</h6><span class=\"align-middle " .
                            $alignmentclass . "\"><p>" . $hideaction .
                            "</p></span>" . $videocontainerstart .
                            "<iframe " . $iframeclass . " src=\"https://youtube.com/embed/" . $values->link . "\"
                            allowfullscreen></iframe></div><br>";
                    } else {
                        return "<h5>" . $OUTPUT->render($tmpl) . "</h5><h6 class=\"card-subtitle mb-2 text-muted\">" .
                            userdate($values->timecreated) . "</h6><span class=\"align-middle " .
                            $alignmentclass . "\"><p>" . $showaction .
                            "</p></span>" . $videocontainerstart .
                            "<iframe " . $iframeclass . " src=\"https://youtube.com/embed/" . $values->link . "\"
                            allowfullscreen></iframe></div><br>";
                    }
                }
                if (has_capability('mod/jitsi:hide', $context) && has_capability('mod/jitsi:deleterecord', $context)) {
                    if ($record->visible != 0) {
                        return "<h5>" . $OUTPUT->render($tmpl) . "</h5><h6 class=\"card-subtitle mb-2 text-muted\">" .
                            userdate($values->timecreated) . "</h6><span class=\"align-middle " .
                            $alignmentclass . "\"><p>" . $deleteaction .
                            "" . $hideaction . "</p></span>" . $videocontainerstart .
                            "<iframe " . $iframeclass . " src=\"https://youtube.com/embed/" . $values->link . "\"
                            allowfullscreen></iframe></div><br>";
                    } else {
                        return "<h5>" . $OUTPUT->render($tmpl) . "</h5><h6 class=\"card-subtitle mb-2 text-muted\">" .
                            userdate($values->timecreated) . "</h6><span class=\"align-middle " .
                            $alignmentclass . "\"><p>" . $deleteaction .
                            "" . $showaction . "</p></span>" . $videocontainerstart .
                            "<iframe " . $iframeclass . " src=\"https://youtube.com/embed/" . $values->link . "\"
                            allowfullscreen></iframe></div><br>";
                    }
                }
                if (!has_capability('mod/jitsi:hide', $context) && !has_capability('mod/jitsi:deleterecord', $context)) {
                    return "<h5>" . $OUTPUT->render($tmpl) . "</h5><h6 class=\"card-subtitle mb-2 text-muted\">" .
                        userdate($values->timecreated) . "</h6><br>" . $videocontainerstart . "<iframe " . $iframeclass .
                        " src=\"https://youtube.com/embed/" . $values->link . "\"
                        allowfullscreen></iframe></div>";
                }
            } else {
                return "<h5>" . $OUTPUT->render($tmpl) . "</h5><h6 class=\"card-subtitle mb-2 text-muted\">" .
                    userdate($values->timecreated) . "</h6><br>" . $videocontainerstart . "<iframe " . $iframeclass .
                    " src=\"https://youtube.com/embed/" . $values->link . "\"
                    allowfullscreen></iframe></div>";
            }
        } else {
            return  "<iframe class=\"embed-responsive-item\" src=\"https://youtube.com/embed/\"
                allowfullscreen></iframe></div>";
        }
    }
}
