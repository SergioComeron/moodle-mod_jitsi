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
        if ($sourcerecord->id && $sourcerecord->link != null && isset($sourcerecord->type) && $sourcerecord->type == 1) {
            // External link (from recordingLinkAvailable event: Dropbox, file, etc.).
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

            $editurl = new moodle_url('/mod/jitsi/view.php', [
                'id' => $cm->id,
                'editrecordid' => $record->id,
                'tab' => 'record',
            ]);
            $editicon = new pix_icon('t/edit', get_string('edit'));
            $editaction = $OUTPUT->action_icon($editurl, $editicon);

            $actions = '';
            if ($jitsi->sessionwithtoken == 0) {
                if (has_capability('mod/jitsi:deleterecord', $context) && has_capability('mod/jitsi:hide', $context)) {
                    $actions = ($record->visible != 0) ? $deleteaction . $hideaction : $deleteaction . $showaction;
                } else if (has_capability('mod/jitsi:deleterecord', $context)) {
                    $actions = $deleteaction;
                } else if (has_capability('mod/jitsi:hide', $context)) {
                    $actions = ($record->visible != 0) ? $hideaction : $showaction;
                }
                $isjibriorgs = strpos($sourcerecord->link, 'storage.googleapis.com') !== false
                    || preg_match('/^http:\/\/\d+\.\d+\.\d+\.\d+\//', $sourcerecord->link);
                if (has_capability('mod/jitsi:record', $context) && !$isjibriorgs) {
                    $actions .= $editaction;
                }
            }

            $isgcs = strpos($sourcerecord->link, 'storage.googleapis.com') !== false;
            $isdropbox = !empty($sourcerecord->embed) && strpos($sourcerecord->link, 'dropbox.com') !== false;
            if ($isdropbox || $isgcs) {
                if ($isdropbox) {
                    $embedurl = preg_replace('/([?&])dl=\d/', '$1raw=1', $sourcerecord->link);
                    if (strpos($embedurl, 'raw=1') === false) {
                        $embedurl .= (strpos($embedurl, '?') !== false ? '&' : '?') . 'raw=1';
                    }
                } else {
                    $embedurl = $sourcerecord->link;
                }

                // AI buttons (GCS only).
                $aibuttonshtml = '';
                if ($isgcs && has_capability('mod/jitsi:generateaisummary', $context)) {
                    $aibuttonshtml .= '<button type="button" class="btn btn-sm btn-outline-primary jitsi-ai-summary-btn"'
                        . ' data-sourcerecordid="' . (int)$sourcerecord->id . '"'
                        . ' data-cmid="' . (int)$cm->id . '">'
                        . '✨ ' . get_string('generateaisummary', 'jitsi')
                        . '</button>'
                        . '<span class="jitsi-ai-summary-status ms-2 text-muted small" style="display:none"></span>';
                }
                if ($isgcs && has_capability('mod/jitsi:generateaiquiz', $context)) {
                    $aibuttonshtml .= ' <button type="button" class="btn btn-sm btn-outline-success jitsi-ai-quiz-btn"'
                        . ' data-sourcerecordid="' . (int)$sourcerecord->id . '"'
                        . ' data-cmid="' . (int)$cm->id . '">'
                        . '&#128221; ' . get_string('aiquizgenerate', 'jitsi')
                        . '</button>'
                        . '<span class="jitsi-ai-quiz-status ms-2 text-muted small" style="display:none"></span>';
                }
                if ($aibuttonshtml) {
                    $aibuttonshtml = '<div class="mt-2">' . $aibuttonshtml . '</div>';
                }

                // Display existing AI summary if available.
                $aisummarytext = '';
                if ($isgcs && !empty($sourcerecord->ai_summary)) {
                    $aisummarytext = '<div class="jitsi-ai-summary-text mt-3 p-3 bg-light rounded">'
                        . '<strong>✨ ' . get_string('aisummary', 'jitsi') . '</strong><br>'
                        . nl2br(s($sourcerecord->ai_summary))
                        . '</div>';
                }

                // Display link to AI quiz if available.
                $aiquizlink = '';
                if ($isgcs && !empty($sourcerecord->ai_quiz_id) && $sourcerecord->ai_quiz_id > 0) {
                    $quizurl = new moodle_url('/mod/quiz/view.php', ['id' => $sourcerecord->ai_quiz_id]);
                    $aiquizlink = '<div class="mt-2">'
                        . html_writer::link(
                            $quizurl,
                            '&#128221; ' . get_string('aiquizview', 'jitsi'),
                            ['class' => 'btn btn-sm btn-success', 'target' => '_blank']
                        )
                        . '</div>';
                }

                $content = "<h5>" . $OUTPUT->render($tmpl) . "</h5>"
                    . "<h6 class=\"card-subtitle mb-2 text-muted\">" . userdate($values->timecreated) . "</h6>"
                    . "<span class=\"align-middle " . $alignmentclass . "\"><p>" . $actions . "</p></span>"
                    . "<video controls style=\"width:100%;max-width:100%\">"
                    . "<source src=\"" . s($embedurl) . "\" type=\"video/mp4\">"
                    . "</video>"
                    . "<p><a href=\"" . s($sourcerecord->link) . "\" target=\"_blank\""
                    . " class=\"btn btn-sm btn-outline-secondary mt-1\">"
                    . get_string('openrecording', 'jitsi') . "</a></p>"
                    . $aibuttonshtml
                    . $aisummarytext
                    . $aiquizlink
                    . "<br>";
            } else {
                $is8x8 = strpos($sourcerecord->link, '8x8.vc') !== false;
                $btnlabel = $is8x8 ? get_string('download') : get_string('openrecording', 'jitsi');
                $openlink = html_writer::link(
                    $sourcerecord->link,
                    $btnlabel,
                    ['target' => '_blank', 'class' => 'btn btn-sm btn-primary']
                );

                // Detect Jibri recordings (served directly from a GCP VM IP).
                $jibriwarn = '';
                if (preg_match('/^http:\/\/\d+\.\d+\.\d+\.\d+\//', $sourcerecord->link)) {
                    $jibriwarn = ' <small class="text-warning ms-1" title="'
                        . s(get_string('jibrirecordingoffline', 'jitsi')) . '">⚠</small>';
                }

                $content = "<div class=\"d-flex align-items-center gap-2 py-1\">"
                    . "<span class=\"flex-grow-1\">"
                    . $OUTPUT->render($tmpl)
                    . $jibriwarn
                    . " <small class=\"text-muted ms-2\">" . userdate($values->timecreated) . "</small>"
                    . "</span>"
                    . "<span class=\"text-nowrap\">" . $actions . $openlink . "</span>"
                    . "</div>";
            }

            return $content;
        }
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
