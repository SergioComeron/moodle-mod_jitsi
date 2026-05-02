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
        global $DB, $OUTPUT, $CFG, $USER;

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

                // AI state flags.
                $summaryerrorstrs = [
                    get_string('aisummaryerror', 'jitsi'),
                    get_string('aisummarynotavailable', 'jitsi'),
                ];
                $summaryisfailed = in_array($sourcerecord->ai_summary ?? '', $summaryerrorstrs);
                $summaryexists = !empty($sourcerecord->ai_summary) && !$summaryisfailed;
                $quizid = (int)($sourcerecord->ai_quiz_id ?? 0);
                if ($quizid > 0 && !$DB->record_exists('course_modules', ['id' => $quizid])) {
                    $DB->set_field('jitsi_source_record', 'ai_quiz_id', 0, ['id' => $sourcerecord->id]);
                    $quizid = 0;
                }

                $videoid = 'jitsi-video-' . (int)$sourcerecord->id;
                $aiid = 'jitsi-ai-' . (int)$sourcerecord->id;

                $transcriptionstatus = $sourcerecord->ai_transcription_status ?? '';
                $transcriptiondone = ($transcriptionstatus === 'done') && !empty($sourcerecord->ai_transcription);

                $aienabled = (bool)get_config('mod_jitsi', 'aienabled');
                $cangensum = $aienabled && $isgcs && has_capability('mod/jitsi:generateaisummary', $context);
                $cangenquiz = $aienabled && $isgcs && has_capability('mod/jitsi:generateaiquiz', $context);
                $cangentrans = $aienabled && $isgcs && has_capability('mod/jitsi:generateaitranscription', $context);

                // Build AI dropdown button (generate options only, shown above the video).
                $bstoggle = $CFG->branch >= 500 ? 'data-bs-toggle' : 'data-toggle';
                $aidropdownitems = '';
                if ($cangensum && !$summaryexists) {
                    $aidropdownitems .= '<li><a class="dropdown-item jitsi-ai-generate" href="#"'
                        . ' data-method="mod_jitsi_queue_ai_summary"'
                        . ' data-sourcerecordid="' . (int)$sourcerecord->id . '"'
                        . ' data-cmid="' . (int)$cm->id . '">'
                        . '<i class="fa fa-align-left me-1" aria-hidden="true"></i>'
                        . get_string('generateaisummary', 'jitsi') . '</a></li>';
                }
                if ($cangenquiz && $quizid <= 0) {
                    $aidropdownitems .= '<li><a class="dropdown-item jitsi-ai-generate" href="#"'
                        . ' data-method="mod_jitsi_queue_ai_quiz"'
                        . ' data-sourcerecordid="' . (int)$sourcerecord->id . '"'
                        . ' data-cmid="' . (int)$cm->id . '">'
                        . '<i class="fa fa-list-check me-1" aria-hidden="true"></i>'
                        . get_string('aiquizgenerate', 'jitsi') . '</a></li>';
                }
                if ($cangentrans && !$transcriptiondone) {
                    if ($transcriptionstatus === 'pending') {
                        $aidropdownitems .= '<li><span class="dropdown-item disabled">'
                            . '<i class="fa fa-microphone me-1" aria-hidden="true"></i>'
                            . get_string('aitranscriptionqueued', 'jitsi') . '</span></li>';
                    } else {
                        $aidropdownitems .= '<li><a class="dropdown-item jitsi-ai-generate" href="#"'
                            . ' data-method="mod_jitsi_queue_ai_transcription"'
                            . ' data-sourcerecordid="' . (int)$sourcerecord->id . '"'
                            . ' data-cmid="' . (int)$cm->id . '">'
                            . '<i class="fa fa-microphone me-1" aria-hidden="true"></i>'
                            . get_string('generateaitranscription', 'jitsi') . '</a></li>';
                    }
                }
                $aidropdown = '';
                if ($aidropdownitems !== '') {
                    $aidropdown = '<div class="dropdown d-inline-block ms-1">'
                        . '<button type="button" class="btn btn-sm btn-outline-secondary dropdown-toggle"'
                        . ' ' . $bstoggle . '="dropdown" aria-expanded="false">'
                        . '<i class="fa fa-wand-magic-sparkles text-primary me-1"'
                        . ' aria-hidden="true"></i>AI</button>'
                        . '<ul class="dropdown-menu">' . $aidropdownitems . '</ul>'
                        . '</div>';
                }

                // Build accordion showing ONLY already-generated AI content (no generate buttons).
                $aitabs = [];
                if ($summaryexists) {
                    $aitabs[] = [
                        'id'      => $aiid . '-summary',
                        'label'   => get_string('aisummary', 'jitsi'),
                        'content' => '<div class="p-2" style="font-size:0.95em">'
                            . nl2br(s($sourcerecord->ai_summary)) . '</div>',
                    ];
                }
                if ($quizid > 0) {
                    $quizurl = new moodle_url('/mod/quiz/view.php', ['id' => $quizid]);
                    $aitabs[] = [
                        'id'      => $aiid . '-quiz',
                        'label'   => get_string('aiquiz', 'jitsi'),
                        'content' => html_writer::link(
                            $quizurl,
                            '&#128221; ' . get_string('aiquizview', 'jitsi'),
                            ['class' => 'btn btn-sm btn-success', 'target' => '_blank']
                        ),
                    ];
                }
                if ($transcriptiondone) {
                    $lines = explode("\n", $sourcerecord->ai_transcription);
                    $transcriptionlines = '';
                    foreach ($lines as $line) {
                        $line = trim($line);
                        if ($line === '') {
                            continue;
                        }
                        if (preg_match('/^###\s+(.+)$/u', $line, $match)) {
                            $transcriptionlines .= '<div class="jitsi-transcript-chapter mt-3 mb-1">'
                                . '<strong>' . s($match[1]) . '</strong></div>';
                        } else if (preg_match('/^\[(\d+):(\d{2})(?::(\d{2}))?\]\s*(.*)$/u', $line, $tm)) {
                            if (isset($tm[3]) && $tm[3] !== '') {
                                $seconds = (int)$tm[1] * 3600 + (int)$tm[2] * 60 + (int)$tm[3];
                                $tslabel = s($tm[1] . ':' . $tm[2] . ':' . $tm[3]);
                            } else {
                                $seconds = (int)$tm[1] * 60 + (int)$tm[2];
                                $tslabel = s($tm[1] . ':' . $tm[2]);
                            }
                            $transcriptionlines .= '<div class="jitsi-transcript-line mb-1">'
                                . '<a href="#" class="jitsi-transcript-ts badge bg-secondary me-2'
                                . ' text-decoration-none"'
                                . ' data-video="' . s($videoid) . '" data-seconds="' . $seconds . '">'
                                . $tslabel . '</a>'
                                . '<span>' . s($tm[4]) . '</span></div>';
                        } else {
                            $transcriptionlines .= '<div class="jitsi-transcript-line mb-1">'
                                . '<span>' . s($line) . '</span></div>';
                        }
                    }
                    $aitabs[] = [
                        'id'      => $aiid . '-transcription',
                        'label'   => get_string('aitranscription', 'jitsi'),
                        'content' => '<div style="max-height:300px;overflow-y:auto;font-size:0.9em">'
                            . $transcriptionlines . '</div>',
                    ];
                }

                $aiaccordion = '';
                if (!empty($aitabs)) {
                    $navtabs  = '';
                    $tabpanes = '';
                    foreach ($aitabs as $idx => $tab) {
                        $active   = $idx === 0 ? 'active' : '';
                        $navtabs .= '<li class="nav-item" role="presentation">'
                            . '<button class="nav-link ' . $active . ' py-1 px-2"'
                            . ' style="font-size:0.85em"'
                            . ' data-bs-toggle="tab" data-bs-target="#' . s($tab['id']) . '"'
                            . ' type="button" role="tab">'
                            . $tab['label'] . '</button></li>';
                        $tabpanes .= '<div class="tab-pane fade ' . ($active ? 'show active' : '') . ' pt-2"'
                            . ' id="' . s($tab['id']) . '" role="tabpanel">'
                            . $tab['content'] . '</div>';
                    }
                    $aiaccordion = '<div class="mt-2 border rounded">'
                        . '<ul class="nav nav-tabs nav-sm mb-0 px-2 pt-1" role="tablist">'
                        . $navtabs . '</ul>'
                        . '<div class="tab-content p-2 bg-light rounded-bottom">'
                        . $tabpanes . '</div>'
                        . '</div>';
                }

                // Load existing watched segments for this user to pre-render the bar.
                $segrow = null;
                $existingsegs = [];
                $existingdur  = 0;
                if (get_config('mod_jitsi', 'portal_license_key')) {
                    $segrow = $DB->get_record('jitsi_recording_segments', [
                        'userid'         => $USER->id,
                        'sourcerecordid' => (int)$sourcerecord->id,
                        'cmid'           => (int)$cm->id,
                    ]);
                    if ($segrow) {
                        $existingsegs = json_decode($segrow->segments, true) ?? [];
                        $existingdur  = (float)($segrow->duration ?? 0);
                    }
                }
                $barhtml = '';
                if (get_config('mod_jitsi', 'portal_license_key')) {
                    $barsegsjson = htmlspecialchars(json_encode($existingsegs), ENT_QUOTES, 'UTF-8');
                    $barhtml = '<div class="mt-2 mb-1"'
                        . ' data-segments="' . $barsegsjson . '"'
                        . ' data-duration="' . $existingdur . '"'
                        . ' id="jitsi-segbar-wrap-' . (int)$sourcerecord->id . '">'
                        . jitsi_render_segments_bar(
                            $existingsegs,
                            $existingdur,
                            'jitsi-segbar-' . (int)$sourcerecord->id
                        )
                        . '<small class="text-muted" id="jitsi-segbar-pct-' . (int)$sourcerecord->id . '">'
                        . ($existingdur > 0 ? jitsi_segments_watched_pct($existingsegs, $existingdur) . '%' : '')
                        . '</small>'
                        . '</div>';
                }

                $heatmaphtml = '';
                if (
                    get_config('mod_jitsi', 'portal_license_key')
                    && has_capability('mod/jitsi:viewattendance', $context)
                ) {
                    $heatmaphtml = jitsi_render_heatmap_bar((int)$sourcerecord->id, (int)$cm->id);
                }

                $content = "<h5>" . $OUTPUT->render($tmpl) . "</h5>"
                    . "<h6 class=\"card-subtitle mb-2 text-muted\">" . userdate($values->timecreated) . "</h6>"
                    . "<div class=\"d-flex align-items-center justify-content-end gap-1 mb-1\">"
                    . $actions . $aidropdown . "</div>"
                    . "<video id=\"" . s($videoid) . "\" controls style=\"width:100%;max-width:100%\""
                    . " data-sourcerecordid=\"" . (int)$sourcerecord->id . "\""
                    . " data-cmid=\"" . (int)$cm->id . "\">"
                    . "<source src=\"" . s($embedurl) . "\" type=\"video/mp4\">"
                    . "</video>"
                    . $barhtml
                    . $heatmaphtml
                    . $aiaccordion
                    . "<br>";
            } else {
                $is8x8 = strpos($sourcerecord->link, '8x8.vc') !== false;
                $btnlabel = $is8x8 ? get_string('download') : get_string('openrecording', 'jitsi');
                $openlink = html_writer::link(
                    $sourcerecord->link,
                    $btnlabel,
                    [
                        'target' => '_blank',
                        'class'  => 'btn btn-sm btn-primary jitsi-recording-link',
                        'data-sourcerecordid' => (int)$sourcerecord->id,
                        'data-cmid'           => (int)$cm->id,
                    ]
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
                        allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe></div><br>";
                }
                if (has_capability('mod/jitsi:hide', $context) && !has_capability('mod/jitsi:deleterecord', $context)) {
                    if ($record->visible != 0) {
                        return "<h5>" . $OUTPUT->render($tmpl) . "</h5><h6 class=\"card-subtitle mb-2 text-muted\">" .
                            userdate($values->timecreated) . "</h6><span class=\"align-middle " .
                            $alignmentclass . "\"><p>" . $hideaction .
                            "</p></span>" . $videocontainerstart .
                            "<iframe " . $iframeclass . " src=\"https://youtube.com/embed/" . $values->link . "\"
                            allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe></div><br>";
                    } else {
                        return "<h5>" . $OUTPUT->render($tmpl) . "</h5><h6 class=\"card-subtitle mb-2 text-muted\">" .
                            userdate($values->timecreated) . "</h6><span class=\"align-middle " .
                            $alignmentclass . "\"><p>" . $showaction .
                            "</p></span>" . $videocontainerstart .
                            "<iframe " . $iframeclass . " src=\"https://youtube.com/embed/" . $values->link . "\"
                            allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe></div><br>";
                    }
                }
                if (has_capability('mod/jitsi:hide', $context) && has_capability('mod/jitsi:deleterecord', $context)) {
                    if ($record->visible != 0) {
                        return "<h5>" . $OUTPUT->render($tmpl) . "</h5><h6 class=\"card-subtitle mb-2 text-muted\">" .
                            userdate($values->timecreated) . "</h6><span class=\"align-middle " .
                            $alignmentclass . "\"><p>" . $deleteaction .
                            "" . $hideaction . "</p></span>" . $videocontainerstart .
                            "<iframe " . $iframeclass . " src=\"https://youtube.com/embed/" . $values->link . "\"
                            allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe></div><br>";
                    } else {
                        return "<h5>" . $OUTPUT->render($tmpl) . "</h5><h6 class=\"card-subtitle mb-2 text-muted\">" .
                            userdate($values->timecreated) . "</h6><span class=\"align-middle " .
                            $alignmentclass . "\"><p>" . $deleteaction .
                            "" . $showaction . "</p></span>" . $videocontainerstart .
                            "<iframe " . $iframeclass . " src=\"https://youtube.com/embed/" . $values->link . "\"
                            allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe></div><br>";
                    }
                }
                if (!has_capability('mod/jitsi:hide', $context) && !has_capability('mod/jitsi:deleterecord', $context)) {
                    return "<h5>" . $OUTPUT->render($tmpl) . "</h5><h6 class=\"card-subtitle mb-2 text-muted\">" .
                        userdate($values->timecreated) . "</h6><br>" . $videocontainerstart . "<iframe " . $iframeclass .
                        " src=\"https://youtube.com/embed/" . $values->link . "\"
                        allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe></div>";
                }
            } else {
                return "<h5>" . $OUTPUT->render($tmpl) . "</h5><h6 class=\"card-subtitle mb-2 text-muted\">" .
                    userdate($values->timecreated) . "</h6><br>" . $videocontainerstart . "<iframe " . $iframeclass .
                    " src=\"https://youtube.com/embed/" . $values->link . "\"
                    allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe></div>";
            }
        } else {
            return  "<iframe class=\"embed-responsive-item\" src=\"https://youtube.com/embed/\"
                allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe></div>";
        }
    }
}
